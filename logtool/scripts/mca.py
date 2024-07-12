import tempfile
import os

from logtool.backend.db import MyDB
from logtool.backend.parsers.mce import ACDExtractor
from logtool.model.parsed import FMToolCrashdump

if __name__ == "__main__":
    for idx, log in enumerate(MyDB().iterate_fmtool_logs()):
        if log.logtype != "crashdump":
            continue
        acd = FMToolCrashdump.model_validate(log.model_dump())
        ppins = acd.ppins
        if not acd.summary:
            continue
        mcas = ACDExtractor.extract_mcas_from_summary(acd.summary)
        print(ppins)
        print(len(mcas))
        print(mcas[:3])
