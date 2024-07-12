import enum

from log_analyzer.utils.file import FileType, get_contents
from log_analyzer.loggers import logger


class LogType(enum.Enum):
    shc = enum.auto()
    onekeylog = enum.auto()
    unknown = enum.auto()


def log_classify(filepath: str):
    with open(filepath, "rb") as f:
        lt = FileType.detect(f.read())
    for ftype, fpath in get_contents(filepath, archive_depth=1):
        if (lt in FileType.compressed_types() or lt in FileType.archive_types()) and (ftype is FileType.txt) and (fpath.endswith("/report.txt") or fpath.endswith("/report.json")):
            logger.debug(f"Inferred to be SHC log as log contains {fpath}")
            return LogType.shc
        if "/onekeylog/" in fpath:
            logger.debug(
                f'Inferred to be onekeylog as {fpath} contains "/onekeylog/"')
            return LogType.onekeylog
    return LogType.unknown


if __name__ == "__main__":
    import logging
    logger.setLevel(logging.DEBUG)
    paths = [
        "/mnt/nvme0n1/shizy/logs/SHC_INBOUND_LOG/28B802454_shc_report_2023-08-08-20-09-48.tar.xz",
        "/mnt/nvme0n1/shizy/log_analyzer/test/parsers/logs/21AC37405.7z",
    ]
    for p in paths:
        t = log_classify(p)
        print(t)
