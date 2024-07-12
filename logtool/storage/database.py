import sqlalchemy as sa
import sqlalchemy.orm as so
import sqlalchemy_utils as su
import sqlalchemy.pool as sq


DB_FILE = "/home/shizy/logtool/fhm.sqlite"
SQLITE_URL = f"sqlite:///{DB_FILE}"
if not su.database_exists(SQLITE_URL):
    su.create_database(SQLITE_URL)

# https://docs.sqlalchemy.org/en/20/core/pooling.html#using-connection-pools-with-multiprocessing-or-os-fork
engine = sa.create_engine(SQLITE_URL, poolclass=sq.NullPool)

SessionLocal = so.sessionmaker(bind=engine)


class FhmStorageBase(so.DeclarativeBase):
    pass
