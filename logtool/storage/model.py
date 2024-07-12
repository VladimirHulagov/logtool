import datetime
import dataclasses
import typing

import sqlalchemy as sa
import sqlalchemy.orm as so

from .database import FhmStorageBase


@dataclasses.dataclass
class FhmLogOrm(FhmStorageBase):
    __tablename__ = "fhm"
    sha256: so.Mapped[str] = so.mapped_column(primary_key=True)
    filename: so.Mapped[str]
    logtype: so.Mapped[str]
    content: so.Mapped[bytes] = so.mapped_column(sa.BLOB)
