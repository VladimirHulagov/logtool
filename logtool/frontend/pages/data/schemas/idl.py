import typing
import datetime

import pydantic

class IdlCategory(pydantic.BaseModel):
    cat: typing.Literal["DIMM", "PCIe", "Thermal", "PowerSupply",
                        "Fan", "CPU", "Bios", "OS", "BMC", "Other", "MainBoard"]
    severity: typing.Literal["Info", "Warn", "Error", "Fatal"]

    @property
    def short_str(self):
        return f"{self.cat}.{self.severity}"


class IdlRegex(IdlCategory):
    pattern: typing.Pattern

    def match(self, text: str):
        match = self.pattern.fullmatch(text)
        return match
        # if match is None:
        #     return None
        # return match.groupdict() or True


_table = {
    "DIMM": {
        "Warn": [
            r"P(?P<cpu>\d+)_C(?P<channel>\d+)_D(?P<slot>\d+)_Status Correctable ECC.*",
        ],
        "Error": [
            r"P(?P<cpu>\d+)_C(?P<channel>\d+)_D(?P<slot>\d+)_Status Memory Device Disabled.*",
            r"P(?P<cpu>\d+)_C(?P<channel>\d+)_D(?P<slot>\d+)_Status Uncorrectable ECC.*",
        ]
    },
    "PCIe": {
        "Warn": [
            r".*Bus Correctable Error Occured( PCIE Location:(?P<location>.*))?",
            r"Current pcie device is not match pcie topology",
            r"Pcie topology not match",
            r"Retimer_err State Asserted RetimerIndex: (\d+)",
        ],
        "Error": [
            r".*Bus Uncorrectable Error Occured( PCIE Location:(?P<location>.*))?",
            r".*Bus Fatal Error Occured( PCIE Location:(?P<location>.*))?",
        ],
    },
    "Thermal": {
        "Warn": [
            r".*CPU Pin Out prochot PECI_CPU(?P<cpu>\d+)_PROCHOT.*",
            r"Index:(?P<cpu>\d+) CPU Pin Out thermal trip.*",
            r"CPU(?P<cpu>\d+)_Status CPU Thermal Trip Occured",
            r"CPU(?P<cpu>\d+)_Status CPU Processor Automatically Throttled",
            r"CPU(?P<cpu>\d+)_Temp reading (?P<temperature>\d+\.\d+) higher than threshold \d+\.\d+(?P<detail>.*)",
            r"OCP_Temp reading (?P<temperature>\d+\.\d+) higher than threshold \d+\.\d+(?P<detail>.*)",
            r"Inlet_Temp reading (?P<temperature>\d+\.\d+) higher than threshold \d+\.\d+(?P<detail>.*)",
        ],
        "Info": [
            r"CPU(?P<cpu>\d+)_Temp Deassert.*",
            r"Inlet_Temp Deassert.*",
            r"OCP_Temp Deassert.*",
        ]
    },
    "PowerSupply": {
        "Warn": [
            r"PSU(?P<psu>\d+)_Supply Power Supply input lost \(AC/DC\)",
            r"PSU(?P<psu>\d+)_Supply Power Supply input lost or out-of-range.*",
            r"PSU(?P<psu>\d+)_Supply Power Supply Failure detected",
            r"PSU(?P<psu>\d+)_Supply Pre-Warning Predictive Failure Occured for Power Supply  - Assert",
            r"B_PSU(?P<psu>\d+)_Supply Power Supply input lost \(AC/DC\)",
            r"Abnormal power failure.*",
            r"B_Redundant_PSU Redundancy Lost",
            r"Redundant_PSU Redundancy Lost",
            r"Redundant_PSU Redundancy Lost  - Assert",
            r"Power_Fault State Asserted",
        ],
        "Info": [
            r"PSU(?P<psu>\d+)_Status Power Supply Equipment Presence detected.*",
            r"PSU(?P<psu>\d+)_Supply Power Supply Equipment Presence detected.*",
            r"B_PSU(?P<psu>\d+)_Supply Power Supply Equipment Presence detected",
            r"PSU(?P<psu>\d+)_Supply Pre-Warning Predictive Failure Occured for Power Supply  - Deassert",
            r"Redundant_PSU Redundancy Lost  - Deassert",
        ],
    },
    "MainBoard": {
        "Warn": [
            r"SYS_3.3V reading (?P<voltage>\d+\.\d+) higher than threshold (?P<threshold>\d+\.\d+)(?P<detail>.*)",
        ],
        "Info": [
            r"SYS_3.3V Deassert.*",
        ]
    },
    "Fan": {
        "Info": [
            r"FAN(?P<fan>\d+)_Present Device Present.*",
            r"FAN(?P<fan>\d+)_Present Device Absent",
            r"B_FAN_Err State Asserted FanIndex: (?P<fan>\d+)",
            r"SYS_FAN_Status Transition to OK(?P<detail>[\s\S]*)",
        ]
    },
    "CPU": {
        "Warn": [
            r"CPU(?P<cpu>\d+)_Status CPU Machine Check Exception.*",
            # r"CPU(?P<cpu>\d+)_Status CPU Machine Check Exception CPU-\d+ Configuration Error: BankType=(?P<bank>\w+), ErrorType=Cache, Severity=Corrected Error",
            r"CPU(?P<cpu>\d+)_Status CPU Configuration Error",
            r"CPU(?P<cpu>\d+)_Status CPU Correctable Machine Check Error",
        ],
        "Error": [
            r"CPU(?P<cpu>\d+)_Status CPU Core Disable CPU-\d+ Configuration Error: BankType=(?P<bank>\w+), ErrorType=Unknown, Severity=Uncorrectable Error",
            r"CPU(?P<cpu>\d+)_Status CPU FRB2/hang in post failure",
        ],
        "Fatal": [
            r"SYS Error  IERR.*",
            r"Fatal\(CATERR/MSMI\) BACD",
            r"CPU(?P<cpu>\d+)_Status CPU Catterror/IERR Occured",
        ],
        "Info": [
            r"CPU(?P<cpu>\d+)_Status CPU Processor Presence detected",
        ]
    },
    "Bios": {
        "Info": [
            r"BIOS_Boot_Up System Initiated by power up",
            r"BIOS_Boot_Up System Initiated by hard reset.*",
            r"BIOS Upgrade.*",
            r"ACPI_State S0/G0 working",
            r"ACPI_State S5/G2 - soft-off",
            r"ACPI_PWR S0/G0 working  - Assert",
            r"ACPI_PWR S4/S5 - soft-off  - Assert",
        ]
    },
    "OS": {
        "Info": [
            r"BMC_Boot System Initiated by power up BMC first boot up",
            r"BMC_Boot_Up System Initiated by warm reset.*",
            r"BMC_Boot_Up System Initiated by power up.*",
            r"SYS_Boot System Initiated by hard reset.*",
            r"SYS_Boot System Initiated by power up.*",
            r"OS_Boot System boot completed - boot device not specified",
        ],
        "Warn": [
            r"Host OS Kernel Panic  BACB",
        ]
    },
    "BMC": {
        "Info": [
            r"BMC Upgrade.*",
            r"Event_Log Log Area Reset/Cleared",
        ]
    },
    "Other": {
        "Info": [
            r"BOX_Link_Status Transition to Non-Critical from OK",
            r"BOX_Link_Status Transition to OK",
            r"CPU(?P<cpu>\d+)_C(?P<channel>\d+)D(?P<slot>\d+) Memory Presence detected.*",
            r"B_SysHeal_Status Transition to Non-Critical from OK",
            r"B_SysHeal_Status Transition to OK",
            r"Power_Button Power Button Pressed Happened  Power Button Long Pressed",
            r"Power_Button Power Button Pressed Happened  Power Button Short Pressed",
            r"ME Transition to Non-Critical from OK.*",
        ]
    }
}

idl_regexes = [
    IdlRegex(cat=cat, severity=severity, pattern=pattern)
    for cat, subtable in _table.items()
    for severity, patterns in subtable.items()
    for pattern in patterns
]


class IdlEntry(pydantic.BaseModel):
    time: datetime.datetime
    src: str
    dir: str
    severity: str
    data: str
    detail: str
    raw: str

    @staticmethod
    def parse_line(line: str):
        elems = line.split("|")
        return IdlEntry(
            time=elems[1],
            src=elems[2],
            dir=elems[3],
            severity=elems[4],
            data=elems[5],
            detail=elems[6].strip(),
            raw=line,
        )

    @property
    def error_cat(self):
        _ = filter(lambda r: r.match(self.detail), idl_regexes)
        matches = list(_)
        assert len(matches) <= 1, matches
        cat = IdlCategory(**matches[0].model_dump()) if matches else None
        return cat

    @property
    def component(self) -> str | None:
        return self.error_cat.cat if self.error_cat else None

    @property
    def severity2(self) -> str | None:
        return self.error_cat.severity if self.error_cat else None

    @property
    def short_str(self):
        return f"{self.severity2} {self.src} {self.detail}"
