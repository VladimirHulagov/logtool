import os
import tempfile
import shutil
import multiprocessing

from logtool.model.logs.shc import ShcParser
from logtool.model.logs.mce import extract_mcas
from logtool.scripts.shc_package import SHCPackageInfoList, SHCPackageInfo, SHCPackageInfoViewList, GroupedResultByPPINList, GroupedResultByPPINViewList, GroupedResultByPPIN

import logging

logger = logging.getLogger()
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)


logsdir = "/home/shizy/logs/SHC_INBOUND_LOG"


def parse_shc_package(logpath: str):
    fname = os.path.basename(logpath)
    try:
        mcas = None
        shc = None
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                shutil.unpack_archive(logpath, tmpdir)
            except Exception as e:
                logger.error("Broken Archive %s", fname)
                return SHCPackageInfo(filename=fname, exception=repr(e))
            for root, _, files in os.walk(tmpdir):
                for f in files:
                    fpath = os.path.join(root, f)
                    if f.startswith("sys") and f.endswith(".log"):
                        # assert mcas is None
                        assert not mcas
                        mcas = extract_mcas(fpath)
                    if f == "report.json":
                        assert shc is None
                        with open(f) as fp:
                            shc = ShcParser().parse(fp.read())
        return SHCPackageInfo(filename=fname, mcas=mcas, shc=shc)
    except Exception as e:
        logger.exception("Fail to parse %s", fname)
        return SHCPackageInfo(filename=fname, exception=repr(e))


workdir = os.path.dirname(__file__)
full_json = os.path.join(workdir, "full.json")
failures_json = os.path.join(workdir, "failures.json")


def _extract(param: tuple[int, str]):
    idx, path = param
    logger.info("Parsing log %s %s", idx, path)
    return parse_shc_package(path)


if __name__ == "__main__":
    logpaths = map(lambda f: os.path.join(logsdir, f), os.listdir(logsdir)[:])
    full = SHCPackageInfoList(list=[])

    def save():
        with open(full_json, "w") as f:
            f.write(full.model_dump_json())
    with multiprocessing.Pool(processes=64) as pool:
        _ = pool.imap_unordered(_extract, enumerate(logpaths))
        for idx, info in enumerate(_):
            full.list.append(info)
            if (idx + 1) % 1000 == 0:
                save()
        save()

    with open(full_json, "r") as f:
        full = SHCPackageInfoViewList.model_validate_json(f.read())

    from collections import Counter
    from pprint import pprint
    counter = Counter(res.filename[:9] for res in full.list)
    pprint(Counter(counter.values()))
    counter = Counter(
        type(res.ppins[0]) if res.ppins else None for res in full.list)
    pprint(Counter(counter.values()))
    # 65 logs without PPIN in SHC
    print(counter.most_common(5))

    failures = {}
    for package in full.list:
        if package.ppins is None:
            continue
        if not (package.shc_failed or package.mcas):
            continue
        for index in enumerate(package.ppins):
            if index not in failures:
                failures[index] = []
            failures[index].append(package)

    abonormals = GroupedResultByPPINList(list=[])
    for index in failures:
        (socket, ppin) = index
        abonormals.list.append(GroupedResultByPPIN(
            ppin=ppin, socket=socket, packages=failures[index]))

    def save():
        with open(failures_json, "w") as f:
            f.write(abonormals.model_dump_json())
    save()

    with open(failures_json, "r") as f:
        abonormals = GroupedResultByPPINList.model_validate_json(f.read())
    print(len(abonormals.list))
