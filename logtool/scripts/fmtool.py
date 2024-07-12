import json
import multiprocessing
from collections import Counter
from pprint import pprint

from logtool.backend.db import MyDB, FMToolLog
from logtool.backend.tmp_db import FileMeta

from logtool.model.logs.syslog import SyslogParser, Syslog

status_codes_json = "/home/shizy/logtool/logtool/scripts/mca_status.json"

with open(status_codes_json) as f:
    status_codes = json.load(f)

status_codes = []


def parse_syslog(param: tuple[int, FMToolLog]):
    idx, log = param
    meta = FileMeta(name=log.filename, sha256=log.sha256code)
    if log.raw_bytes.decode().count("\\n") > 20:
        print("XXXXXXXXXXx")
        return None
    # print(f"{idx}\t{log.filename:<100}")
    try:
        res: Syslog | None = SyslogParser().parse(log.raw_bytes)
    except Exception:
        return None
    return meta, res
    content = log.raw_bytes.decode().lower()
    counter = Counter()
    for c in status_codes:
        cnt = content.count(c) - content.count(f"ppin {c}")
        if cnt:
            counter[c] += cnt
    counts = sum(counter.values())
    if not res:
        assert counts == 0
        print(idx, log.filename, None)
        return meta, res
    print(f"{idx}\t{log.filename:<100} {counts:10}\t{len(res.mcas)}")
    # TODO: Handle those logs with CE storms
    if counts > len(res.mcas) * 1.01:
        if "mce: [Hardware Error]: CPU".lower() in content:
            # Unsupported new log type
            return res
        counter2 = Counter(hex(mca.status) for mca in res.mcas)
        print("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
        print(log.filename)
        pprint(counter)
        pprint(counter2)
        print(len(res.mcas))
        print("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
        raise 1
    return res


if __name__ == "__main__":
    db = MyDB()
    _ = db.iterate_fmtool_logs()
    _ = filter(lambda log: log.logtype == "ossyslog", _)
    _ = filter(lambda log: "fmtool" not in log.submitter, _)
    msmcacods = Counter()
    codes2 = set()
    with multiprocessing.Pool(32) as pool:
        _ = pool.imap_unordered(parse_syslog, enumerate(_))
        # _ = map(parse_syslog, enumerate(_))
        _ = filter(None, _)
        for meta, r in _:
            if r is None:
                continue
            if any(((mca.status & 0xFFFFFFFF) == 0x00300e0f) for mca in r.mcas):
                print(meta)
