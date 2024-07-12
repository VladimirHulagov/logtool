import pathlib
import json
from pprint import pprint
from collections import Counter
from datetime import timezone, tzinfo
from zoneinfo import ZoneInfo

from logtool.utils.file import ArchiveFile
from logtool.model.logs.syslog import SyslogParser, Syslog
from logtool.model.abstract import EventSeverity

archive_path = pathlib.Path(
    "/home/shizy/logs/FleetHealthManagement/Raw/Kuaishou/intel_log_0526-0705.tar.gz")
archive = ArchiveFile(archive_path)

if __name__ == "__main__":
    with archive:
        _ = archive.getmembers()
        _ = filter(lambda m: m.isfile(), _)
        members = list(_)
        for m in members:
            result_ms = [mem for mem in members if m.name +
                         ".result" == mem.name]
            if not result_ms:
                continue
            assert len(result_ms) == 1
            result_m = result_ms[0]
            result = json.loads(archive.extract(result_m).read().decode())
            if result["FHM_Result"]["Issue"] == "UNKNOWN ISSUE(Empty)" and result["Summarizer_Result"]["FaultReason"] == "Null":
                continue
            syslog: Syslog | None = SyslogParser(
                sel_tz=ZoneInfo("Asia/Shanghai")
            ).parse(archive.extract(m).read().decode())
            assert syslog is not None
            print(m.name)
            if not syslog.mcas or True:
                print(result["FHM_Result"]["Issue"])
                print(result["FHM_Result"]["Suggestion"])
                print(result["Summarizer_Result"]["FaultReason"])
                print(result["Summarizer_Result"]["FaultAction"])
                _ = syslog.key_events
                _ = map(lambda e: e.event_index, syslog.key_events)
                _ = filter(lambda v: v.severity is not EventSeverity.Info, _)
                events = sorted(
                    _, key=lambda e: e.time.astimezone(timezone.utc))
                for e in events:
                    print(e.time, e.type, e.description[:50])
