import pathlib
import tempfile
import datetime
import itertools
import functools
import contextlib
import typing

import sqlalchemy as sa
import sqlalchemy.orm as so

from . import model
from ..api.fhm import Metadata


def get_log(session: so.Session, sha256: str):
    info = (
        session
        .query(model.FhmLogOrm)
        .filter(model.FhmLogOrm.sha256 == sha256)
        .one_or_none()
    )
    return info and (info.sha256, info.filename, info.content)


def get_sha256s(session: so.Session):
    sha256s = (
        session
        .query(model.FhmLogOrm.sha256)
        .all()
    )
    return [sha256.tuple()[0] for sha256 in sha256s]


def put_log(session: so.Session, meta: Metadata, content: bytes):
    log = get_log(session, meta.sha256code)
    if log is not None:
        return log
    log = model.FhmLogOrm(
        sha256=meta.sha256code,
        filename=meta.filename,
        logtype=meta.logtype,
        content=content,
    )
    session.add(log)
    return log
