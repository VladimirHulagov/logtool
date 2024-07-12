import pathlib
import itertools
import typing

import pydantic

from ..base import MachineCheckBase

from .util import AnyParam

from .text_parser import TextParser, ContentPattern


def _create_parser(cls: MachineCheckBase, pattern: ContentPattern):
    def try_validate(d: dict):
        try:
            return cls.model_validate(d)
        except pydantic.ValidationError:
            if __debug__:
                raise
            return None

    def _parser(text: str):
        p = TextParser(p=pattern)
        _ = p.bulk_parse(text=text)
        _ = map(try_validate, _)
        _ = filter(None, _)
        return list(_)
    return _parser


parsers = []


def register_parser(cls: MachineCheckBase, pattern: ContentPattern):
    parsers.append(_create_parser(cls, pattern))


def parse_mce(input: typing.Union[str, bytes, pathlib.Path]):
    assert len(parsers) > 0
    text = AnyParam.from_input(input=input).as_str()
    _ = map(lambda p: p(text), parsers)
    _ = itertools.chain.from_iterable(_)
    return list(_)


def parse_acd(input: typing.Union[str, bytes, pathlib.Path]):
    import tempfile
    import contextlib
    import io
    from pysvtools.crashdump_summarizer.cd_summarizer import summary
    from .json_based.acd import AcdSummary
    acd = AnyParam.from_input(input=input)
    with tempfile.TemporaryDirectory() as tmpdir, acd.mkfile("acd.json") as acd_path:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            summary(str(acd_path), text_file=False, dest=tmpdir)
        stderr.seek(0)
        files = list(pathlib.Path(tmpdir).glob("*.json"))
        err = stderr.read()
        if "JSON might be corrupted!" in err:
            raise ValueError(f"Summarizer found corrupted json")
        elif err:
            raise RuntimeError(f"Summarizer internal error: {err}")
        if len(files) != 1:
            raise RuntimeError("Summarizer fail to generate summary.")
        with open(files[0]) as f:
            content = f.read()
            if not __debug__:
                return AcdSummary.model_validate_json(content)
            try:
                return AcdSummary.model_validate_json(content)
            except Exception:
                import json
                res = {k: json.dumps(v, indent=2)
                       for k, v in json.loads(content).items()}
                for k, v in res.items():
                    print(k)
                    print(v[:1000])
                raise
