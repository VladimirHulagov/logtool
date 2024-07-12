import pathlib
import typing
import tempfile
import contextlib

import pydantic


class AnyParam(pydantic.BaseModel):
    filepath: typing.Optional[pathlib.Path]
    content: typing.Optional[typing.Union[bytes, str]]

    @staticmethod
    def from_input(input: typing.Union[pathlib.Path, bytes, str]):
        assert isinstance(input, (pathlib.Path, bytes, str))
        if isinstance(input, pathlib.Path):
            return AnyParam(filepath=input, content=None)
        else:
            assert isinstance(input, (bytes, str))
            return AnyParam(filepath=None, content=input)

    # TODO: cache conversion result
    @contextlib.contextmanager
    def mkfile(self, name: typing.Optional[str] = None):
        if self.filepath is not None:
            yield self.filepath
            return
        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = pathlib.Path(tmpdir).joinpath(name or "temp")
            with open(fpath, "wb") as f:
                f.write(self.as_bytes())
            yield fpath
            return

    def as_bytes(self):
        if self.filepath is not None:
            assert self.filepath
            with open(self.filepath, "rb") as f:
                return f.read()
        if isinstance(self.content, bytes):
            return self.content
        assert isinstance(self.content, str)
        return self.content.encode()

    def as_str(self):
        if isinstance(self.content, str):
            return self.content
        return self.as_bytes().decode()
