import json
import multiprocessing
from collections import Counter

from logtool.model.filemeta import FMToolLogMeta
from logtool.api.fmtool import fmtool_download_log
from logtool.backend.db import MyDB

import logging
logger = logging.getLogger()
log_formatter = logging.Formatter(
    "[%(asctime)s][%(levelname)s][%(name)s][%(module)s][%(funcName)s] %(message)s")
handler = logging.StreamHandler()
handler.setFormatter(log_formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


def cache_log(db: MyDB, meta: FMToolLogMeta):
    if db.is_fmtool_log_inserted(meta.sha256code):
        return
    try:
        content = fmtool_download_log(meta.hdfs_file_path)
        db.try_insert_fmtool_log(meta, content)
        logger.info("Downloaded log %s", meta.filename)
    except Exception as e:
        logger.exception("Fail to download log %s", meta.filename)


_db = MyDB()


def _cache_log(meta: FMToolLogMeta):
    return cache_log(_db, meta)


if __name__ == "__main__":
    db = MyDB()
    # with open("/home/shizy/logtool/logtool/scripts/metadata.json") as f:
    #     _ = json.load(f)
    # _ = map(FMToolLogMeta.model_validate, _)
    # _ = filter(lambda meta: "ziyan.shi@intel.com" not in meta.submitter, _)
    # _ = filter(lambda meta: meta.logtype in [
    #            "crashdump", "onekeylog", "ossyslog"], _)
    # _ = filter(lambda meta: meta.logtype in ["ossyslog"], _)
    # print(Counter(log.logtype for log in _))
    # with multiprocessing.Pool(processes=32) as pool:
    #     _ = pool.imap_unordered(_cache_log, _)
    #     list(_)
    _ = db.iterate_fmtool_logs()
    _ = filter(lambda meta: meta.logtype in ["ossyslog"], _)
    _ = filter(lambda meta: "ziyan.shi@intel.com" not in meta.submitter, _)
    for log in _:
        print(log.filename)
        from logtool.model.logs.fhm import FmtoolSyslogResult, FmtoolSyslogParser
        res: FmtoolSyslogResult = FmtoolSyslogParser().parse(log.raw_bytes)
        print(res.model_dump_json(indent=2))
