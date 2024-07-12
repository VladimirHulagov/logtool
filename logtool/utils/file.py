import os
import re
import enum
import tempfile
import pathlib
import abc
import typing
import dataclasses


import magic
import zipfile
import py7zr
import tarfile
import gzip
import rarfile
import lzma
import bz2


def list_files(dir_path: str):
    for (parent, dirs, files) in os.walk(dir_path):
        for f in files:
            p = os.path.join(parent, f)
            # Sometimes there are pipes under a folder!!!
            if os.path.isfile(p):
                yield p


class FileType(enum.Enum):
    # Archives
    zip = "application/zip"
    _7z = "application/x-7z-compressed"
    tar = "application/x-tar"
    rar = "application/x-rar"
    # Compressed
    gz = "application/gzip"
    bz2 = "application/x-bzip2"
    xz = "application/x-xz"
    # Text
    txt = "text/plain"
    xml = "text/xml"
    html = "text/html"
    # Code
    sh = "text/x-shellscript"
    py = "text/x-python"
    bat = "text/x-msdos-batch"
    diff = "text/x-diff"
    rtf = "text/rtf"   # Rich Text Format
    c = "text/x-c"   # Maybe asm
    cpp = "text/x-c++"  # Maybe System Verilog
    tex = "text/x-tex"  # Maybe a plain log
    json = "application/json"
    # Image
    gif = "image/gif"
    jpg = "image/jpeg"
    png = "image/png"
    svg = "image/svg"
    svgx = "image/svg+xml"
    webp = "image/webp"
    tiff = "image/tiff"
    pcx = "image/x-pcx"
    bmp = "image/x-ms-bmp"
    ico = "image/x-icon"
    # Video
    mkv = "video/x-matroska"
    mp4 = "video/mp4"
    mov = "video/quicktime"
    webm = "video/webm"
    # Executable
    elf = "application/x-executable"  # Linux executable
    msi = "application/x-msi"
    exe = "application/x-dosexec"
    so = "application/x-sharedlib"
    rpm = "application/x-rpm"
    # Documents
    pdf = "application/pdf"
    msg = "application/vnd.ms-outlook"
    xls = "application/vnd.ms-excel"
    ppt = "application/vnd.ms-powerpoint"
    xlsx = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    pptx = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
    docx = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    # Binary
    bin = "application/octet-stream"
    # Unknown
    eml = "message/rfc822"
    dsn = "application/CDFV2"
    empty = "application/x-empty"
    # Really unknown
    unk = ""

    @property
    @staticmethod
    def archive_types():
        return [
            FileType.zip,
            FileType._7z,
            FileType.tar,
            FileType.rar,
        ]

    @property
    @staticmethod
    def compressed_types():
        return [
            FileType.gz,
            FileType.bz2,
            FileType.xz,
        ]

    @property
    @staticmethod
    def unknown_types():
        return [
            FileType.eml,
            FileType.dsn,
            FileType.empty,
        ]

    @property
    @staticmethod
    def known_incorrect_types():
        return [
            FileType.c,
            FileType.cpp,
            FileType.tex,
        ]

    @staticmethod
    def detect(bin: bytes):
        t = magic.from_buffer(bin, mime=True)
        for typ in FileType:
            if t == typ.value:
                return typ
        # TODO(ziyan): Fix unsupported types
        # return FileType.unk
        raise NotImplementedError(t)


_ArchiveFile = tarfile.TarFile | zipfile.ZipFile
_ArchiveInfo = tarfile.TarInfo | zipfile.ZipInfo


def zipinfo_isfile(info: zipfile.ZipInfo):
    return not info.is_dir()


class ArchiveInfo():
    @dataclasses.dataclass
    class _ArchiveInfoFunctions():
        # name: typing.Callable[[_ArchiveFile], str]
        name_attr: str
        isdir: typing.Callable[[_ArchiveFile], bool]
        isfile: typing.Callable[[_ArchiveFile], bool]

    configs = {
        tarfile.TarInfo: _ArchiveInfoFunctions(
            # lambda info: info.name,
            "name",
            tarfile.TarInfo.isdir,
            tarfile.TarInfo.isfile,
        ),
        zipfile.ZipInfo: _ArchiveInfoFunctions(
            # lambda info: info.filename,
            "filename",
            zipfile.ZipInfo.is_dir,
            zipinfo_isfile,
        ),
    }

    def __init__(self, info: _ArchiveInfo):
        self.info = info
        self._funcs = self.configs[type(info)]

    @property
    def name(self) -> str:
        # return self._funcs.name(self.info)
        return getattr(self.info, self._funcs.name_attr)

    def isdir(self):
        return self._funcs.isdir(self.info)

    def isfile(self):
        return self._funcs.isfile(self.info)


class ArchiveFile():
    @dataclasses.dataclass
    class _ArchiveFunctions():
        open: typing.Callable[[pathlib.Path], _ArchiveFile]
        getmembers: typing.Callable[[_ArchiveFile], list[_ArchiveInfo]]
        extract: typing.Callable[
            [_ArchiveFile, _ArchiveInfo],
            typing.IO[bytes]
        ]   # TODO: Check for tarfile.TarFile.extractfile None return

    configs = {
        tarfile: _ArchiveFunctions(
            tarfile.open,
            tarfile.TarFile.getmembers,
            tarfile.TarFile.extractfile,
        ),
        zipfile: _ArchiveFunctions(
            zipfile.ZipFile,
            zipfile.ZipFile.infolist,
            zipfile.ZipFile.open,
        )
    }

    def __init__(self, path: pathlib.Path):
        suffix = path.suffix
        # if suffix in [".tar", ".tar.gz", ".tar.xz"]:
        if suffix in [".gz", ".xz"]:
            self._funcs = self.configs[tarfile]
        elif suffix in [".zip"]:
            self._funcs = self.configs[zipfile]
        else:
            raise ValueError("Unsupported type")
        self._archive = self._funcs.open(path)

    def __enter__(self):
        self._archive.__enter__()
        return self

    def __exit__(self, t, v, tr):
        self._archive.__exit__(t, v, tr)
        return None

    def getmembers(self):
        return [ArchiveInfo(m) for m in self._funcs.getmembers(self._archive)]

    def extract(self, info: ArchiveInfo):
        return self._funcs.extract(self._archive, info.info)


# def get_contents_deprecated(filepath: str, archive_depth=1):
#     filename = os.path.basename(filepath)
#     logger.debug(f"Processing {filepath}")
#     assert os.path.isfile(filepath), os.stat(filepath)
#     with open(filepath, "rb") as f:
#         content = f.read()
#     t = FileType.detect(content)
#     logger.debug(f"Type: {t}")
#     # Compressed file, decompress, then get_contents() again
#     decompressors = {
#         FileType.gz: gzip.decompress,
#         FileType.xz: lzma.decompress,
#         FileType.bz2: bz2.decompress,
#     }
#     if t in FileType.compressed_types():
#         with tempfile.TemporaryDirectory() as tmpdir:
#             fname = filename.removesuffix(f".{t.name}")
#             decompress_path = os.path.join(tmpdir, fname)
#             with open(decompress_path, "wb") as f:
#                 f.write(decompressors[t](content))
#             for res in get_contents_deprecated(decompress_path, archive_depth):
#                 yield res
#             return
#     # Archive, extract all, then get_contents() for each file
#     archive_formats = {
#         FileType.zip: zipfile.ZipFile,
#         FileType._7z: py7zr.SevenZipFile,
#         FileType.tar: tarfile.TarFile,
#         FileType.rar: rarfile.RarFile,
#     }
#     if t in FileType.archive_types():
#         logger.debug(f"Extracting from {filepath}")
#         if archive_depth == 0:
#             logger.debug(f"Skipping {filepath} as archive_depth limit is reached.")
#             yield (t, filepath)
#             return
#         try:
#             with tempfile.TemporaryDirectory() as tmpdir:
#                 with archive_formats[t](filepath) as archive:
#                     archive.extractall(tmpdir)
#                 logger.debug(f"Extracted {filepath}")
#                 for fpath in list_files(tmpdir):
#                     for res in get_contents_deprecated(fpath, archive_depth - 1):
#                         yield res
#                 return
#         except py7zr.PasswordRequired:
#             logger.info(f"Skipping {filepath} as archive is encrypted.")
#             yield (t, filepath)
#         except rarfile.PasswordRequired:
#             logger.info(f"Skipping {filepath} as archive is encrypted.")
#             yield (t, filepath)
#         # zipfile
#         except RuntimeError as e:
#             if "password required" in repr(e):
#                 logger.info(f"Skipping {filepath} as archive is encrypted.")
#                 yield (t, filepath)
#                 return
#             raise
#     # Plain file, return directly
#     yield (t, filepath)
#     return
