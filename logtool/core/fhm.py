import io
import pathlib
import contextlib

import pydantic


class FmtoolSyslogResult(pydantic.BaseModel):
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


def fhm_diag_syslog(syslog: pathlib.Path):
    from fmtool_sdk.log_diagnosis import decode_ossyslog, diagnose_ossyslog
    stdout = io.StringIO()
    stderr = io.StringIO()
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            res = diagnose_ossyslog(decode_ossyslog(str(syslog)), False)
        return FmtoolSyslogResult.model_validate(res.to_dict())
    except Exception:
        return FmtoolSyslogResult(
            diagnose="",
            issue="FMTool SDK Internal Error",
            suggestion="Contact Intel",
        )


class FmtoolAcdResult(pydantic.BaseModel):
    summ_category: str
    summ_suggestion: str
    bafi_issue: str
    bafi_diagnose: str
    bafi_suggestion: str
    bafi_fru: str


def fhm_diag_acd(acd: pathlib.Path):
    from fmtool_sdk.log_diagnosis import decode_crashdump, diagnose_crashdump
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        res = diagnose_crashdump(decode_crashdump(str(acd)))
    # return FmtoolSyslogResult.model_validate(res.diagnose_result())
