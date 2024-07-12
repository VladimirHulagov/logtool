import pathlib
import argparse
from pprint import pprint

import pydantic

from logtool.utils.file import ArchiveFile, ArchiveInfo

logs_dir = pathlib.Path("/home/shizy/logs/FleetHealthManagement")


class Args(pydantic.BaseModel):
    filename: str


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--filename", "-f")
    arg = Args.model_validate(parser.parse_args().__dict__)
    print(arg.model_dump())

    for log in logs_dir.rglob("*"):
        if not log.is_file():
            continue
        if arg.filename in log.name:
            print("Found log")
            print(log)
            exit()

    for log in logs_dir.rglob("*"):
        if not log.is_file():
            continue
        if not any(log.name.lower().endswith(s) for s in [".zip", ".tar.gz"]):
            continue
        if log.stat().st_size > 100_000_000:
            continue
        if "__MACOSX" in str(log):
            continue
        print(log)
        print(log.stat().st_size)
        try:
            a = ArchiveFile(log)
        except Exception:
            continue
        with ArchiveFile(log) as a:
            for m in a.getmembers():
                if arg.filename in m.name:
                    print("Found log")
                    print(log)
                    print(m.name)
                    exit()
