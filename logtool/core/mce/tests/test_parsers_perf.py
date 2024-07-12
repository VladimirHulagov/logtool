import re

import pytest

from .. import (
    parse_mce,
    MachineCheckBase,
)
from .conftest import (
    LogInfo,
    spr100k_syslogs,
)


@pytest.mark.parametrize("log", spr100k_syslogs)
def test_spr100k_logs_benchmark(log: LogInfo, prepare_log, benchmark):
    log = prepare_log(log)
    mces = benchmark(parse_mce, log.text)
