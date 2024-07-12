import pathlib
import multiprocessing
import itertools
from collections import Counter

from .profile import profile
from logtool.core.mce import parse_mce, decode_mce
from logtool.core.systeminfo import SystemInfo
from logtool.core.fhm import fhm_diag_syslog, FmtoolSyslogResult

logsdir = pathlib.Path(__file__).parent.parent.joinpath(
    "logtool", "core", "mce", "tests", "logs", "spr100k_syslog")

print(logsdir)


def parse_syslog(logpath: pathlib.Path):
    print(f"Processing {logpath}")
    sysinfo = SystemInfo(mces=parse_mce(logpath))
    fhmdiag = fhm_diag_syslog(logpath)
    print(f"Processed {logpath}")
    return logpath, sysinfo, fhmdiag


def get_logs():
    _ = logsdir.rglob("*.log")
    _ = list(_)[:10]
    _ = filter(lambda p: p.is_file(), _)
    _ = map(parse_syslog, _)
    return list(_)


@profile
def parse_mces():
    def parse(log: pathlib.Path):
        try:
            print(log)
            mces = parse_mce(log)
            decodes = [decode_mce("SPR", mce) for mce in mces]
            print(len(mces))
            print(mces[0].short_str)
            print(decodes[0].model_dump_json(indent=4))
            return mces, decodes
        except Exception as ex:
            print(repr(ex))
            return None
    _ = logsdir.rglob("*.log")
    _ = itertools.islice(_, 10)
    _ = map(parse, _)
    return list(_)


@profile
def get_triage():
    def summarize(log: tuple[pathlib.Path, SystemInfo, FmtoolSyslogResult]):
        print("XXXXXXXXXXXXXxx")
        triage = log[1].triage
        return {
            "Logname": log[0].name,
            "signature": "\t".join(t.category.value for t in triage) if triage else "\t".join(set(f"Bank {mce.bank} | {hex(mce.status & 0xFFFF_FFFF)}" for mce in sysinfo.mces)),
            "suggestion": "\n".join(t.suggestion for t in triage),
            "FhmIssue": log[2].issue,
            "FhmSuggestion": log[2].suggestion
        }
    logs = get_logs()
    _ = map(summarize, logs)
    return list(_)


if __name__ == "__main__":
    parse_mces()
