import pathlib
import io
import contextlib

import pydantic

from logtool.model.interface import ISerializableParsedLog, IParser, EventSeverity


class FmtoolSyslogResult(pydantic.BaseModel, ISerializableParsedLog):
    diagnose: str = pydantic.Field(
        validation_alias=pydantic.AliasChoices(
            pydantic.AliasPath("diagnose_result", "diagnose"),
            "diagnose"
        )
    )
    issue: str = pydantic.Field(
        validation_alias=pydantic.AliasChoices(
            pydantic.AliasPath("diagnose_result", "issue"),
            "issue"
        )
    )
    suggestion: str = pydantic.Field(
        validation_alias=pydantic.AliasChoices(
            pydantic.AliasPath("diagnose_result", "suggestion"),
            "suggestion"
        )
    )

    @property
    def key_events(self):
        return [self]

    @property
    def time(self):
        return None

    @property
    def signature(self):
        return f"{self.issue}"

    @property
    def description(self):
        return f"{self.suggestion}"

    @property
    def _severity(self) -> EventSeverity:
        return EventSeverity.Info


class FmtoolSyslogParser(IParser):
    def parse_impl(self, syslog: pathlib.Path):
        import sys
        sys.path.append("..")
        from fmtool_sdk.log_diagnosis import decode_ossyslog, diagnose_ossyslog
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            res = diagnose_ossyslog(decode_ossyslog(syslog), False)
        return FmtoolSyslogResult.model_validate(res.to_dict())

    def check_impl(self, syslog: pathlib.Path):
        return True


class FmtoolAcdResult(pydantic.BaseModel, ISerializableParsedLog):
    summ_category: str
    summ_suggestion: str
    bafi_issue: str
    bafi_diagnose: str
    bafi_suggestion: str
    bafi_fru: str

    @property
    def key_events(self):
        return [self]

    @property
    def time(self):
        return None

    @property
    def signature(self):
        return f"{self.bafi_issue}"

    @property
    def description(self):
        return f"{self.bafi_suggestion}"

    @property
    def _severity(self) -> EventSeverity:
        return EventSeverity.Critical


class FmtoolAcdParser(IParser):
    @property
    def _path_suffix(self):
        return ".json"

    def parse_impl(self, acd: pathlib.Path):
        import sys
        sys.path.append("..")
        from fmtool_sdk.log_diagnosis import decode_crashdump, diagnose_crashdump
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            res = diagnose_crashdump(decode_crashdump(acd))
        bafi = res.diagnose_result
        summ = res.summarizer_diagnose
        return FmtoolAcdResult(
            summ_category=summ.category,
            summ_suggestion=summ.suggestion,
            bafi_diagnose=bafi.diagnose,
            bafi_fru=bafi.frucode,
            bafi_issue=bafi.issue,
            bafi_suggestion=bafi.suggestion,
        )

    def check_impl(self, logpath: pathlib.Path):
        logpath = str(logpath)
        from pysvtools.crashdump_summarizer.cd_summarizer import get_json
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            return bool(get_json(logpath))
