import dataclasses
from datetime import datetime

import sqlalchemy as sa
import sqlalchemy.orm as so

from logtool.model.interface import (
    ISerializableParsedLog,
    ISerializableEvent,
    SerializedEvent,
    SerializedParsedLog,
    EventView,
    TaggedSystemDetail,
    TaggedSystemInfo,
    Tag,
    TagType,
    EventSeverity,
    FileMeta,
)


class MyDBBase(so.DeclarativeBase):
    pass


@dataclasses.dataclass
class _TagRawLogAssociationTable(MyDBBase):
    __tablename__ = "tag_rawlog_association_table"
    tag_id = so.mapped_column(
        sa.ForeignKey("tag._id"),
        primary_key=True,
    )
    rawlog_sha256 = so.mapped_column(
        sa.ForeignKey("rawlog.sha256"),
        primary_key=True,
    )


@dataclasses.dataclass
class _TagOrm(MyDBBase):
    __tablename__ = "tag"
    _id: so.Mapped[int] = so.mapped_column(
        primary_key=True, autoincrement=True)
    type: so.Mapped[TagType] = so.mapped_column(index=True)
    value: so.Mapped[str] = so.mapped_column(index=True)
    rawlogs: so.Mapped[list["_RawLogOrm"]] = so.relationship(
        back_populates="tags",
        secondary=_TagRawLogAssociationTable.__tablename__
    )
    __table_args__ = (
        sa.UniqueConstraint("type", "value"),
    )


@dataclasses.dataclass
class _RawLogOrm(MyDBBase):
    __tablename__ = "rawlog"
    sha256: so.Mapped[str] = so.mapped_column(primary_key=True)
    name: so.Mapped[str] = so.mapped_column(index=True)
    tags: so.Mapped[list[_TagOrm]] = so.relationship(
        back_populates="rawlogs",
        secondary=_TagRawLogAssociationTable.__tablename__
    )
    parsed: so.Mapped[list["_ParsedLogOrm"]] = so.relationship(
        back_populates="rawlog",
    )


@dataclasses.dataclass
class _IndexedItem():
    sha256: so.Mapped[str] = so.mapped_column(index=True)
    time: so.Mapped[datetime | None] = so.mapped_column(index=True)
    type: so.Mapped[str] = so.mapped_column(index=True)
    subtype: so.Mapped[str | None] = so.mapped_column(index=True)
    severity: so.Mapped[EventSeverity] = so.mapped_column(index=True)
    signature: so.Mapped[str | None] = so.mapped_column(index=True)
    description: so.Mapped[str | None] = so.mapped_column(index=False)
    json_content: so.Mapped[str] = so.mapped_column(sa.TEXT)


@dataclasses.dataclass
class _ParsedLogOrm(MyDBBase, _IndexedItem):
    __tablename__ = "parsed"
    rawlog_sha256 = so.mapped_column(sa.ForeignKey("rawlog.sha256"))
    rawlog: so.Mapped[_RawLogOrm] = so.relationship(
        back_populates="parsed",
    )
    events: so.Mapped[list["_EventOrm"]] = so.relationship(
        back_populates="parsed_log",
    )
    __table_args__ = (
        sa.PrimaryKeyConstraint("rawlog_sha256", "sha256"),
    )

    def to_event(self):
        return SerializedParsedLog.model_validate(self.__dict__)

    @staticmethod
    def from_event(e: ISerializableParsedLog):
        return _ParsedLogOrm(**e.serialized.model_dump(exclude="detail"))

    @classmethod
    def view_cols(cls):
        return [
            _ParsedLogOrm.sha256,
            _ParsedLogOrm.time,
            _ParsedLogOrm.type,
            _ParsedLogOrm.subtype,
            _ParsedLogOrm.severity,
            _ParsedLogOrm.signature,
            _ParsedLogOrm.description
        ]

    @staticmethod
    def to_view(row: sa.Row):
        return EventView.model_validate(row._mapping)


@dataclasses.dataclass
class _EventOrm(MyDBBase, _IndexedItem):
    __tablename__ = "event"
    _idx: so.Mapped[int] = so.mapped_column(
        autoincrement=True, primary_key=True)
    parsed_log_sha256 = so.mapped_column(sa.ForeignKey("parsed.sha256"))
    parsed_log: so.Mapped[_ParsedLogOrm] = so.relationship(
        back_populates="events",
    )

    def to_event(self):
        return SerializedEvent.model_validate(**dataclasses.asdict(self))

    @staticmethod
    def from_event(e: ISerializableEvent):
        return _EventOrm(**e.serialized.model_dump(exclude="detail"))


class MyDB():
    def __init__(self) -> None:
        self.db_file = "/home/shizy/logtool/parsedlogs.sqlite"
        self._engine = sa.create_engine(
            f"sqlite:///{self.db_file}", echo=False)
        MyDBBase.metadata.create_all(self._engine)

    def upsert_parsed(self, filemeta: FileMeta, log: ISerializableParsedLog):
        ser = log.serialized
        with so.Session(self._engine) as session:
            raw = session.execute(
                sa.select(_RawLogOrm)
                .filter(_RawLogOrm.sha256 == filemeta.sha256)
            ).scalar()
            parsed = session.execute(
                sa.select(_ParsedLogOrm)
                .join(_ParsedLogOrm.rawlog)
                .filter(_ParsedLogOrm.sha256 == ser.sha256)
                .filter(_ParsedLogOrm.rawlog_sha256 == filemeta.sha256)
            ).scalar()
            if raw is None:
                raw = _RawLogOrm(**filemeta.model_dump())
            if parsed is not None:
                session.delete(parsed)
            parsed = _ParsedLogOrm.from_event(log)
            parsed.rawlog = raw
            # parsed.events = [_EventOrm.from_event(e) for e in log.key_events]
            session.add(raw)
            session.add(parsed)
            session.commit()

    def try_add_tag(self, filemeta: FileMeta, tag: Tag):
        with so.Session(self._engine) as session:
            tag_orm = session.execute(
                sa.select(_TagOrm)
                .filter(_TagOrm.type == tag.type)
                .filter(_TagOrm.value == tag.value)
            ).scalar()
            if not tag_orm:
                tag_orm = _TagOrm(**tag.model_dump())
                session.add(tag_orm)
            file_orm = session.execute(
                sa.select(_RawLogOrm)
                .filter(_RawLogOrm.sha256 == filemeta.sha256)
            ).scalar()
            if not file_orm:
                file_orm = _RawLogOrm(**filemeta.model_dump())
                session.add(file_orm)
            assoc = session.execute(
                sa.select(_TagRawLogAssociationTable)
                .filter(_TagRawLogAssociationTable.tag_id == tag_orm._id)
                .filter(_TagRawLogAssociationTable.rawlog_sha256 == file_orm.sha256)
            ).scalar()
            if not assoc:
                file_orm.tags.append(tag_orm)
            session.commit()

    def iterate_logs(self):
        batch_sz = 10
        for i in range(0, 2**20, batch_sz):
            with so.Session(self._engine) as session:
                logs = session.execute(
                    sa.select(_ParsedLogOrm)
                    .order_by(_ParsedLogOrm.sha256.asc())
                    .offset(i)
                    .limit(batch_sz)
                ).scalars().all()
            if not logs:
                return
            for log in logs:
                e = log.to_event()
                yield e

    def iterate_logs_view(self):
        # TODO: don't select detail
        batch_sz = 10
        for i in range(0, 2**20, batch_sz):
            with so.Session(self._engine) as session:
                logs = session.execute(
                    sa.select(*_ParsedLogOrm.view_cols())
                    .select_from(_ParsedLogOrm)
                    .order_by(_ParsedLogOrm.sha256.asc())
                    .offset(i)
                    .limit(batch_sz)
                ).all()
            if not logs:
                return
            for log in logs:
                e = _ParsedLogOrm.to_view(log)
                yield e

    def _get_tags(self, tagtype: TagType):
        with so.Session(self._engine) as session:
            tags = session.execute(
                sa.select(_TagOrm)
                .where(_TagOrm.type == tagtype)
            ).scalars().all()
        return list(tags)

    def iterate_system_info_by_tag(self, tagtype: TagType):
        if tagtype is TagType.Sha256:
            with so.Session(self._engine) as session:
                raw_logs = session.execute(
                    sa.select(_RawLogOrm)
                ).scalars().all()
            for raw in raw_logs:
                with so.Session(self._engine) as session:
                    logs = session.execute(
                        sa.select(*_ParsedLogOrm.view_cols())
                        .filter(_ParsedLogOrm.rawlog_sha256 == raw.sha256)
                    ).all()
                yield TaggedSystemInfo(
                    tag=Tag(type=tagtype, value=raw.sha256),
                    logs=list(map(_ParsedLogOrm.to_view, logs)),
                    raw_logs=[raw.name],
                )
        tags = self._get_tags(tagtype)
        for tag in tags:
            with so.Session(self._engine) as session:
                subq = (
                    sa.select(_RawLogOrm.sha256)
                    .join(_RawLogOrm.tags)
                    .where(_TagOrm._id == tag._id)
                ).subquery()
                logs = session.execute(
                    sa.select(*_ParsedLogOrm.view_cols())
                    .join(_ParsedLogOrm.rawlog)
                    .where(_RawLogOrm.sha256.in_(subq.select()))
                ).all()
                raw = session.execute(
                    sa.select(_RawLogOrm.name)
                    .join(_RawLogOrm.tags)
                    .where(_TagOrm._id == tag._id)
                ).scalars().all()
                yield TaggedSystemInfo(
                    tag=Tag(type=tag.type, value=tag.value),
                    logs=list(map(_ParsedLogOrm.to_view, logs)),
                    raw_logs=list(raw),
                )

    def get_system_detail_by_tag(self, tag: Tag):
        with so.Session(self._engine) as session:
            subq = (
                sa.select(_RawLogOrm.sha256)
                .join(_RawLogOrm.tags)
                .where(_TagOrm.type == tag.type)
                .where(_TagOrm.value == tag.value)
            ).subquery().select()
            if tag.type == TagType.Sha256:
                subq = [tag.value]
            logs = session.execute(
                sa.select(_ParsedLogOrm)
                .join(_ParsedLogOrm.rawlog)
                .where(_RawLogOrm.sha256.in_(subq))
            ).scalars().all()
            return TaggedSystemDetail(
                tag=tag,
                logs=list(map(_ParsedLogOrm.to_event, logs))
            )

    def get_raw_logs(self, sut: str):
        with so.Session(self._engine) as session:
            rawlogs = session.execute(
                sa.select(_RawLogOrm)
                .join(_RawLogOrm.tags)
                .filter(_RawLogOrm.tags.any(_TagOrm.type == TagType.UUID and _TagOrm.value == sut))
            ).scalars()
            return [FileMeta(name=rawlog.name, sha256=rawlog.sha256) for rawlog in rawlogs]


if __name__ == "__main__":
    db = MyDB()
    for tag_view in db.iterate_system_info_by_tag(TagType.UUID):
        print(tag_view.model_dump_json(indent=4))
        print(db.get_system_detail_by_tag(
            tag=tag_view.tag).model_dump_json(indent=4))
        exit()
