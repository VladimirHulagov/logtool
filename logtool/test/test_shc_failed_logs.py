import os
import pytest


from logtool.scripts.spr100k_mc import parse_shc_package

logsdir = "/home/shizy/logtool/logtool/test/logs/spr100k"
files = os.listdir(logsdir)


@pytest.mark.parametrize(argnames="file", argvalues=files)
def disabled_test_parse_package(file: str):
    res = parse_shc_package(os.path.join(logsdir, file))
    if res.exception and "EOFError" in res.exception:
        pytest.skip("Broken package, no need to test")
    assert not res.exception
