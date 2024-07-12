import multiprocessing
import traceback

from ..api import fhm, auth
from ..storage import database, crud

database.FhmStorageBase.metadata.create_all(database.engine)

with database.SessionLocal.begin() as session:
    sha256s = set(crud.get_sha256s(session))

def download_helper(meta: fhm.Metadata):
    if meta.sha256code in sha256s:
        return None
    try:
        fname, content = fhm.download_production_log(meta)
        assert fname == meta.filename
        return meta, content
    except Exception:
        traceback.print_exc()
        return None


def download_crashdumps():
    infos = fhm.get_loginfos(auth.prod_env, "crashdump")
    with multiprocessing.Pool(32) as pool:
        res = pool.imap_unordered(download_helper, infos)
        for meta, content in filter(None, res):
            yield meta, content


if __name__ == "__main__":
    for t in ["crashdump", "onekeylog"]:
        infos = fhm.get_loginfos(auth.prod_env, t)
        for idx, (meta, content) in enumerate(download_crashdumps()):
            with database.SessionLocal.begin() as session:
                crud.put_log(session, meta, content)
                print(idx, meta.filename)
