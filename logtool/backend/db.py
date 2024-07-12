from datetime import datetime
import hashlib
import dataclasses
import enum

import sqlalchemy as sa
import sqlalchemy.orm as so

from logtool.model.filemeta import (
    HSDArticleBase,
    HSDArticle,
    HSDArticleWithAttachment,
    FileBase,
    FMToolLogMeta,
    FMToolLog,
)


class MyDBBase(so.DeclarativeBase):
    pass


def gettsc():
    return datetime.now()


def calc_sha256(content: bytes):
    return hashlib.sha256(content)


@dataclasses.dataclass
class _CachedContent():
    _cache_ts: so.Mapped[datetime] = so.mapped_column(default=gettsc)


@dataclasses.dataclass
class _HSDArticleORM(MyDBBase, _CachedContent):
    __tablename__ = "hsd_articles"
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    article_json: so.Mapped[str] = so.mapped_column(sa.JSON)
    attachments: so.Mapped[list["_HSDAttachmentORM"]] = so.relationship(
        back_populates="hsd")


@dataclasses.dataclass
class _FMToolLogORM(MyDBBase, _CachedContent):
    __tablename__ = "fmtool_logs"
    sha256code: so.Mapped[str] = so.mapped_column(primary_key=True)
    logmeta: so.Mapped[str] = so.mapped_column(sa.JSON)
    raw_bytes: so.Mapped[bytes]


@dataclasses.dataclass
class _HSDAttachmentORM(MyDBBase, _CachedContent):
    __tablename__ = "hsd_attachments"
    url: so.Mapped[str] = so.mapped_column(primary_key=True)
    hsdid = so.mapped_column(sa.ForeignKey("hsd_articles.id"))
    raw_bytes: so.Mapped[bytes]
    hsd: so.Mapped["_HSDArticleORM"] = so.relationship(
        back_populates="attachments")


class LogSource(enum.Enum):
    hsdes = enum.auto()
    fmtool = enum.auto()
    spr100k = enum.auto()


@dataclasses.dataclass
class _ParsedLogORM(MyDBBase, _CachedContent):
    __tablename__ = "parsed_logs"
    sha256code: so.Mapped[str] = so.mapped_column(primary_key=True)
    filename: so.Mapped[str | None] = so.mapped_column(index=True)

    ppin: so.Mapped[int] = so.mapped_column(index=True)
    parsed_json: so.Mapped[bytes] = so.mapped_column(sa.JSON)


class MyDB():
    def __init__(self) -> None:
        db_file = "/home/shizy/logtool/dump-hsdes.sqlite"
        self._engine = sa.create_engine(f"sqlite:///{db_file}", echo=False)
        MyDBBase.metadata.create_all(self._engine)

    def is_article_inserted(self, hsdid: int):
        with so.Session(self._engine) as session:
            article_id = session.execute(
                sa.select(_HSDArticleORM.id)
                .filter(_HSDArticleORM.id == hsdid)
            ).scalar()
            return article_id is not None

    def try_insert_article(self, article: HSDArticleBase):
        if self.is_article_inserted(article.id):
            return
        with so.Session(self._engine) as session:
            a = _HSDArticleORM(
                id=article.id, article_json=article.model_dump_json())
            session.add(a)
            session.commit()

    def count_articles(self):
        with so.Session(self._engine) as session:
            cnt = session.execute(
                sa.select(sa.func.count(_HSDArticleORM.id))
            ).scalar_one()
            return cnt

    def iterate_articles(self):
        batch_sz = 1000
        for i in range(0, 2**20, batch_sz):
            with so.Session(self._engine) as session:
                articles = session.execute(
                    sa.select(_HSDArticleORM)
                    .order_by(_HSDArticleORM.id.desc())
                    .offset(i)
                    .limit(batch_sz)
                ).scalars().all()
            if not articles:
                return
            for article in articles:
                yield HSDArticle.model_validate_json(article.article_json)

    def is_hsd_attachment_inserted(self, url: str):
        with so.Session(self._engine) as session:
            u = session.execute(
                sa.select(_HSDAttachmentORM.url)
                .filter(_HSDAttachmentORM.url == url)
            ).scalar()
            return u is not None

    def try_insert_hsd_attachment(self, hsdid: int, url: str, raw_bytes: bytes):
        if self.is_hsd_attachment_inserted(url):
            return
        with so.Session(self._engine) as session:
            a = _HSDAttachmentORM(hsdid=hsdid, url=url, raw_bytes=raw_bytes)
            session.add(a)
            session.commit()

    def count_attachments(self):
        with so.Session(self._engine) as session:
            cnt = session.execute(
                sa.func.count(_HSDAttachmentORM.url)
            ).scalar_one()
            return cnt

    def get_article(self, hsdid: int):
        with so.Session(self._engine) as session:
            article_orm = session.execute(
                sa.select(_HSDArticleORM)
                .filter(_HSDArticleORM.id == hsdid)
            ).scalar()
        if article_orm is None:
            return None
        article = HSDArticle.model_validate_json(article_orm.article_json)
        return article

    def get_article_with_attachments(self, hsdid: int):
        with so.Session(self._engine) as session:
            article_orm = session.execute(
                sa.select(_HSDArticleORM)
                .filter(_HSDArticleORM.id == hsdid)
                .options(so.joinedload(_HSDArticleORM.attachments))
            ).scalar()
        if article_orm is None:
            return None
        article = HSDArticle.model_validate_json(article_orm.article_json)
        attachments_orm = article_orm.attachments if article_orm.attachments else []
        files = [FileBase(filename="", raw_bytes=att.raw_bytes)
                 for att in attachments_orm]
        for att, f in zip(attachments_orm, files):
            f.filename = article.url_to_name(att.url)
        # TODO: How to init from parent? Use json.loads otherwise
        return HSDArticleWithAttachment(**HSDArticle.model_fields, files=files)

    def is_fmtool_log_inserted(self, sha256: str):
        with so.Session(self._engine) as session:
            h = session.execute(
                sa.select(_FMToolLogORM.sha256code)
                .filter(_FMToolLogORM.sha256code == sha256)
            ).scalar()
            return h is not None

    def try_insert_fmtool_log(self, meta: FMToolLogMeta, content: bytes):
        if self.is_fmtool_log_inserted(meta.sha256code):
            return
        with so.Session(self._engine) as session:
            a = _FMToolLogORM(sha256code=meta.sha256code,
                              logmeta=meta.model_dump_json(),
                              raw_bytes=content)
            session.add(a)
            session.commit()

    def count_fmtool_logs(self):
        with so.Session(self._engine) as session:
            cnt = session.execute(
                sa.func.count(_FMToolLogORM.sha256code)
            ).scalar_one()
            return cnt

    def iterate_fmtool_logs(self):
        metas = self.get_fmtool_logmetas()
        for meta in metas:
            yield self.get_fmtool_log(meta.sha256code)
        # batch_sz = 100
        # for i in range(0, 2**20, batch_sz):
        #     with so.Session(self._engine) as session:
        #         logs = session.execute(
        #             sa.select(_FMToolLogORM)
        #             .order_by(_FMToolLogORM.sha256code.desc())
        #             .offset(i)
        #             .limit(batch_sz)
        #         ).scalars().all()
        #     if not logs:
        #         return
        #     for log in logs:
        #         l = FMToolLogMeta.model_validate_json(log.logmeta)
        #         yield FMToolLog(raw_bytes=log.raw_bytes, **l.model_dump())

    def get_fmtool_logmetas(self):
        with so.Session(self._engine) as session:
            metas = session.execute(
                sa.select(_FMToolLogORM.logmeta)
            ).scalars().all()
        return [FMToolLogMeta.model_validate_json(m) for m in metas]

    def get_fmtool_log(self, sha256: str):
        with so.Session(self._engine) as session:
            log = session.execute(
                sa.select(_FMToolLogORM)
                .filter(_FMToolLogORM.sha256code == sha256)
            ).scalar()
        if log is None:
            return None
        meta = FMToolLogMeta.model_validate_json(log.logmeta)
        return FMToolLog(raw_bytes=log.raw_bytes, **meta.model_dump())


if __name__ == "__main__":
    db = MyDB()
    cnt = db.count_articles()
    print(f"Total articles: {cnt}")
    cnt = db.count_attachments()
    print(f"Total attachments: {cnt}")
    cnt = db.count_fmtool_logs()
    print(f"Total fmtool logs: {cnt}")

    from collections import Counter
    counter = Counter()
    counter2 = Counter()
    for log in db.iterate_fmtool_logs():
        counter[log.submitter] += 1
        if not log.filename.startswith("Ali_"):
            continue
        counter[log.logtype] += 1
    print(counter.most_common(20))
    print(counter2)

    for idx, a in enumerate(db.iterate_articles()):
        break
        print(a.id, a.title)
        a = db.get_article_with_attachments(a.id)
        for att in a.files:
            print(att.filename, att.raw_bytes[:10])
        if list(a.parse_ext_attach_url()):
            exit()

    for log in db.iterate_fmtool_logs():
        break
        print(log.filename, log.content[:100])
