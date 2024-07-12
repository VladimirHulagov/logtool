import os
import re
import io
from datetime import datetime

import zipfile
import py7zr
import tarfile
import gzip
import rarfile

from log_analyzer.loggers import logger


def try_extract(archive_path: str, temp_dir: str, name_regex: str):
    tarfile_subfixes = ("tar.xz", "tar.gz", "tar")
    zipfile_subfixes = ("zip")
    archive_name = os.path.basename(archive_path)
    if any([archive_path.endswith(s) for s in tarfile_subfixes]):
        archive = tarfile.open(archive_path)
        names = archive.getnames()
    else:
        assert any([archive_path.endswith(s) for s in zipfile_subfixes])
        archive = zipfile.ZipFile(archive_path)
        names = archive.namelist()
    matched_names = [n for n in names if re.fullmatch(name_regex, n)]

    if len(matched_names) == 1:
        full_name = matched_names[0]
        archive.extract(full_name, temp_dir)
        dst_path = os.path.join(temp_dir, full_name)
        logger.debug(f"Extracted {full_name} in {archive_name}")
        return dst_path
    elif len(matched_names) == 0:
        logger.debug(f"Nothing matching {name_regex} in {archive_name}.")
        return None
    else:
        logger.error(
            f"Multiple files matching {name_regex} in {archive_name}: {matched_names}")
        return None


def try_extract_file(archive_path: str, name_regex: str) -> io.BufferedReader:
    tarfile_subfixes = ("tar.xz", "tar.gz", "tar")
    archive_name = os.path.basename(archive_path)
    assert any([archive_path.endswith(s) for s in tarfile_subfixes])
    archive = tarfile.open(archive_path)
    names = archive.getnames()
    matched_names = [n for n in names if re.fullmatch(name_regex, n)]

    if len(matched_names) == 1:
        full_name = matched_names[0]
        file = archive.extractfile(full_name)
        logger.debug(f"Extracted {full_name} in {archive_name}")
        return file
    elif len(matched_names) == 0:
        logger.debug(f"Nothing matching {name_regex} in {archive_name}.")
        return None
    else:
        logger.error(
            f"Multiple files matching {name_regex} in {archive_name}: {matched_names}")
        return None


def try_parse_timestamp(timestamp: str):
    from dateutil import parser as dtparser
    try:
        return dtparser.parse(timestamp.replace("_", " ").replace(",", " "))
    except dtparser.ParserError:
        return None


def is_archive(archive_path):
    return get_ext(archive_path) in [
        ".tar.gz",
        ".tar.xz",
        ".zip",
        ".tar", ".tgz", ".tar.gz", ".tar.xz",
        ".gz",
        ".7z",
        ".rar"
    ]


def get_ext(archive_path):
    root, ext = os.path.splitext(archive_path)
    ext = ".tar.gz" if archive_path.endswith(".tar.gz") else ext
    ext = ".tar.xz" if archive_path.endswith(".tar.xz") else ext
    return ext


def try_decompress(archive_path: str, dst: str):
    """Decompress until no recognizable suffix is found"""
    root, ext = os.path.splitext(archive_path)
    ext = ".tar.gz" if archive_path.endswith(".tar.gz") else ext
    ext = ".tar.xz" if archive_path.endswith(".tar.xz") else ext
    try:
        match ext:
            case ".zip":
                with zipfile.ZipFile(archive_path) as zip:
                    zip.extractall(dst)
            case ".tar" | ".tgz" | ".tar.gz" | ".tar.xz":
                with tarfile.open(archive_path) as tar:
                    tar.extractall(dst)
            case ".gz":
                with gzip.open(archive_path) as gz, open(os.path.join(dst, os.path.split(root)[1]), "wb") as f:
                    f.write(gz.read())
            case ".7z":
                py7zr.unpack_7zarchive(archive_path, dst)
            case ".rar":
                with rarfile.RarFile(archive_path) as rar:
                    rar.extractall(dst)
            case _:
                return False
        return True
    except FileNotFoundError:
        # TODO(Ziyan): Why?
        return False


# TODO(Ziyan): Test this function
def recursive_decompress(archive_path: str, dst: str, depth=3):
    assert depth >= 1
    assert os.listdir(dst) == []
    path = shutil.copy(archive_path, dst)

    def _decompress_locally(path):
        if not is_archive(path):
            return False
        dir = path.removesuffix(get_ext(path))
        # TODO(Ziyan): Why existed?
        try:
            os.makedirs(dir, exist_ok=False)
        except FileExistsError:
            return False
        res = try_decompress(path, dir)
        if res:
            os.remove(path)
        return res
    for i in range(depth):
        paths = list(list_files(dst))
        for path in paths:
            res = _decompress_locally(path)
        assert not (i == 0 and not res)
