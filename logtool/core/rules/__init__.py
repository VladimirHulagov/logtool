from .rule import TriageResult, TriageRule
from .cpu.ifu import IfuParityCeTriage, IfuParityUeTriage
from .cpu.dcu import DcuParityCeTriage, DcuParityUeTriage, DcuPoisonTriage
from .cpu.mlc import MlcParityCeTriage, MlcParityUeTriage
from .cpu.cha import ChaParityCeTriage, ChaParityUeTriage
from .dimm.dimm import DimmCeTriage, DimmUeTriage

rules: list[TriageRule] = [
    IfuParityCeTriage(),
    IfuParityUeTriage(),
    DcuParityCeTriage(),
    DcuParityUeTriage(),
    DcuPoisonTriage(),
    MlcParityUeTriage(),
    MlcParityCeTriage(),
    DimmCeTriage(),
    DimmUeTriage(),
    ChaParityUeTriage(),
    ChaParityCeTriage(),
]
