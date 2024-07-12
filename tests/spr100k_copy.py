import pathlib
import multiprocessing
import shutil
import tarfile
import tempfile
import re

spr100k_dir = pathlib.Path("/home/shizy/logs/SHC_INBOUND_LOG")
dst_dir = pathlib.Path(__file__).parent.joinpath("logs", "spr100k")

# spr100k_dir = pathlib.Path(__file__).parent.joinpath("logs", "spr100k")
dst_dir = pathlib.Path(__file__).parent.joinpath("logs", "spr100k_syslog")


def contain_error(logpath: pathlib.Path):
    print(logpath.name)
    regex = re.compile("((status|bank)[^0-9a-f]*(0x)?[89a-f][0-9a-f]{15})", flags=re.IGNORECASE)
    try:
        with tarfile.open(logpath) as archive:
            for m in archive.getmembers():
                if "sys_" in m.name and m.name.endswith(".log"):
                    content = archive.extractfile(m).read().decode()
                    if m := regex.search(content):
                        print(m.group())
                        return logpath
    except Exception:
        return None
        raise

if __name__ == "__main__":
    # for log in names:
    #     shutil.copy2(spr100k_dir.joinpath(log), dst_dir)
    with multiprocessing.Pool(32) as pool:
        _ = spr100k_dir.glob("*.tar.xz")
        _ = pool.map(contain_error, _)
        _ = filter(None, _)
        for p in _:
            with tarfile.open(p) as archive:
                for m in archive.getmembers():
                    if "sys_" in m.name and m.name.endswith(".log"):
                        archive.extract(m, dst_dir)
