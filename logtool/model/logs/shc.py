from datetime import datetime
from typing_extensions import Annotated

from logtool.model.interface import ISerializableEvent, ISerializableParsedLog, IParser, EventSeverity

import pydantic


def ts_parser(ts: str):
    try:
        if ts == "n/a":
            return None
        return datetime.strptime(ts, r"%c")
    except:
        return ts


_ShcTimestamp = Annotated[
    datetime | None,
    pydantic.BeforeValidator(ts_parser)
]


class ShcReport(pydantic.BaseModel, ISerializableParsedLog):
    class SHCSummaryT(pydantic.BaseModel):
        class SHCFailuresT(pydantic.BaseModel):
            SocketFailures: list[str]
            TestsWithFailString: list[str]
        SHCFailures: SHCFailuresT
        SHCOverallResults: Annotated[
            list[str],
            pydantic.AfterValidator(
                lambda l: l if len(l) == 1 else
                AssertionError("Multiple Results!")
            )
        ]

    class SystemInfoT(pydantic.BaseModel):
        class DIMMInfoT(pydantic.BaseModel):
            Locator: str
            Manufacturer: str
            PartNumber: str
            Rank: str
            SerialNumber: str
            Size: str
            Speed: str
            Type: str

        class SocketInfoT(pydantic.BaseModel):
            CPUID_1_0_EAX: str
            PPIN: str
            UCODE: str
        BIOSVersion: str
        CPUCoreCount: int
        CPUModel: str
        CPUSocketCount: int
        CPUTotalLPs: int
        CPUType: str
        Duration: str | None = None
        EndTime: _ShcTimestamp | None = None
        StartTime: _ShcTimestamp
        LogicalDIMMInfo: Annotated[
            list[DIMMInfoT],
            pydantic.BeforeValidator(
                lambda info: info["DIMM(s)"] if isinstance(
                    info, dict) else info
            )
        ]
        SHCVersion: str
        SocketInfo: dict[str, SocketInfoT]
        SystemDescription: str
        SystemName: str
        ToolKitVersion: str

    class SubTestT(pydantic.BaseModel, ISerializableEvent):
        class ResultsT(pydantic.BaseModel):
            ExitCode: str
            Skipped: str
            Stderr: list[str]
            Stdout: list[str]
            TapStrFound: str
            TimeoutReached: str
        Command: str
        Duration: str
        EndTime: _ShcTimestamp
        StartTime: _ShcTimestamp
        Status: str
        TestId: str
        TestType: str
        Results: ResultsT
        TestNumber: int

        @classmethod
        def flatten_test(cls, test: dict):
            # Dumped log
            if "SubTest" not in test:
                return test
            # Raw log
            subtest = test.pop("SubTest")
            assert len(subtest) == 1
            test.update(subtest[0])
            return test

        @property
        def _time(self):
            return self.StartTime

        @property
        def signature(self):
            return self.Status

        @property
        def description(self):
            return f"{self.Status} {self.TestId} {self.TestType}"

        @property
        def _severity(self):
            return EventSeverity.Error

    SHCSummary: SHCSummaryT
    SystemInfo: SystemInfoT
    Test: list[Annotated[SubTestT,
                         pydantic.BeforeValidator(SubTestT.flatten_test)]] | None = None

    def _is_failed_subtest(self, subtest: SubTestT):
        return subtest.TestId in self.SHCSummary.SHCFailures.TestsWithFailString

    @property
    def failed_tests(self) -> list[SubTestT]:
        if self.Test is None:
            return []
        _ = filter(lambda t: self._is_failed_subtest(t), self.Test)
        _ = sorted(_, key=lambda t: t.StartTime)
        return _

    def reduce(self):
        self.Test = self.failed_tests

    @property
    def ppins(self):
        return [int(p.PPIN, 16) for p in self.SystemInfo.SocketInfo.values()]

    @property
    def failed(self):
        return "FAILED - See SHC FAILURES section above for which tests failed" in self.SHCSummary.SHCOverallResults

    @property
    def time(self):
        return self.SystemInfo.StartTime

    @property
    def signature(self):
        return "Pass" if all("PASSED" in r for r in self.SHCSummary.SHCOverallResults) else "Fail"

    @property
    def description(self):
        return "\n".join(self.SHCSummary.SHCOverallResults)

    @property
    def key_events(self):
        return self.failed_tests


class ShcParser(IParser):
    def parse_impl(self, input: str):
        res = ShcReport.model_validate_json(input)
        res.reduce()
        return res

    def check_impl(self, log: str):
        return "SHCSummary" in log and "SystemInfo" in log
