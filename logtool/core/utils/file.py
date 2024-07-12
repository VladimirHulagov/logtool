import enum
import typing
import pathlib
import functools


import magic
import zipfile
import tarfile
# import py7zr
# import gzip
# import rarfile
# import lzma
# import bz2


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
    def __init__(self, info: _ArchiveInfo):
        self.info = info

    @property
    def filename(self):
        return self._getname(self.info)

    def isdir(self):
        return self._isdir(self.info)

    def isfile(self):
        return self._isfile(self.info)

    @functools.singledispatchmethod
    def _getname(self, _) -> str:
        raise NotImplementedError

    @_getname.register
    def _(self, info: tarfile.TarInfo):
        return info.name

    @_getname.register
    def _(self, info: zipfile.ZipInfo):
        return info.filename

    @functools.singledispatchmethod
    def _isdir(self, _):
        raise NotImplementedError

    @_isdir.register
    def _(self, info: tarfile.TarInfo):
        return info.isdir()

    @_isdir.register
    def _(self, info: zipfile.ZipInfo):
        return info.is_dir()

    @functools.singledispatchmethod
    def _isfile(self, _):
        raise NotImplementedError

    @_isfile.register
    def _(self, info: tarfile.TarInfo):
        return info.isfile()

    @_isfile.register
    def _(self, info: zipfile.ZipInfo):
        return not info.is_dir()


class ArchiveFile():
    def __init__(self, path: pathlib.Path):
        with open(path, "rb") as f:
            c = f.read(100_000)
        t = FileType.detect(c)
        # TODO: check archive type
        if t in [FileType.xz, FileType.gz, FileType.tar]:
            a = tarfile.open(path)
        elif t in [FileType.zip]:
            a = zipfile.ZipFile(path)
        else:
            raise ValueError("Not an archive")
        self._archive = a

    def getmembers(self):
        return [ArchiveInfo(m) for m in self._getmembers(self._archive)]

    def extractfile(self, info: ArchiveInfo):
        return self._extractfile(info.info)

    def __enter__(self):
        self._archive.__enter__()
        return self

    def __exit__(self, t, v, tr):
        self._archive.__exit__(t, v, tr)
        return None

    @functools.singledispatchmethod
    def _getmembers(self, _) -> list[_ArchiveInfo]:
        raise NotImplementedError

    @_getmembers.register
    def _(self, file: zipfile.ZipFile):
        return file.filelist

    @_getmembers.register
    def _(self, file: tarfile.TarFile):
        return file.getmembers()

    @functools.singledispatchmethod
    def _extractfile(self, _) -> typing.IO[bytes] | None:
        raise NotImplementedError

    @_extractfile.register
    def _(self, info: zipfile.ZipInfo):
        assert isinstance(self._archive, zipfile.ZipFile)
        return self._archive.open(info)

    @_extractfile.register
    def _(self, info: tarfile.TarInfo):
        assert isinstance(self._archive, tarfile.TarFile)
        return self._archive.extractfile(info)
