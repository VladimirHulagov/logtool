import json
import enum
import regex
from datetime import datetime


def json_dump_readable(obj, file):
    json.dump(obj, file, indent=4)


def json_dumps_readable(obj):
    return json.dumps(obj, indent=4)


def json_dump_compact(obj, file):
    json.dump(obj, file, indent=None, separators=(",", ":"))


def json_dumps_compact(obj):
    return json.dumps(obj, indent=None, separators=(",", ":"))


def to_js_object(obj, max_depth=-1):
    """Convert python object to javascript object.
    """
    if isinstance(obj, (int, str, bool, type(None))):
        return obj
    if max_depth == 0:
        return repr(obj)
    elif isinstance(obj, list):
        return [to_js_object(o, max_depth-1) for o in obj]
    elif isinstance(obj, tuple):
        return tuple(to_js_object(o, max_depth-1) for o in obj)
    elif isinstance(obj, dict):
        return {to_js_object(k): to_js_object(v, max_depth-1) for k, v in obj.items()}
    elif isinstance(obj, enum.Enum):
        return obj.name
    elif isinstance(obj, datetime):
        # TODO(ziyan): Handle objects with circled reference
        return repr(obj)
    else:
        # User defined class
        keys = [k for k in dir(obj) if not k.startswith("_")]
        assert all(isinstance(k, (int, str, enum.Enum)) for k in keys)
        flattened = {k: getattr(obj, k) for k in keys}
        flattened = {k: v for k, v in flattened.items() if not callable(v)}
        flattened = {k: to_js_object(v, max_depth-1)
                     for k, v in flattened.items()}
        return flattened


def jretrieve_node(obj, pred) -> list:
    """Recursively traverse tree of dict and list and retrieve nodes"""
    if pred(obj):
        return [obj]
    elif isinstance(obj, list):
        col = [jretrieve_node(o, pred) for o in obj]
        res = [r for c in col for r in c]
        return res
    elif isinstance(obj, dict):
        col = [([item] if pred(item) else jretrieve_node(item[1], pred))
               for item in obj.items()]
        res = [r for c in col for r in c]
        return res
    else:
        # Terminate
        return []


def jretrive_value(obj, key):
    """Search recursively to retrieve value of fields matching given key"""
    assert isinstance(key, str)
    def pred(item): return isinstance(
        item, tuple) and len(item) == 2 and key == item[0]
    return [v for k, v in jretrieve_node(obj, pred)]


def jretrieve_kv(obj, pred):
    """Search recursively to retrieve fields of given key that satisfy pred"""
    def pred_(item): return isinstance(
        item, tuple) and len(item) == 2 and pred(item[0])
    return jretrieve_node(obj, pred_)


def extract_jsons(txt: str) -> list[str]:
    """Try open the file in text mode, extracting every string conforming to javascript object notation.
    Return a list of strings that can be loaded by json.loads().
    These strings can also be used to split the original string 
    so that if extracted string do match something we can ignore it in the original string.
    """
    assert isinstance(txt, str)
    json_regex = regex.Regex(
        r"(?(DEFINE)"
        r"(?<json>(?>\s*(?&object)\s*|\s*(?&array)\s*))"
        r"(?<object>(?>\{\s*(?>(?&pair)(?>\s*,\s*(?&pair))*)?\s*\}))"
        r"(?<pair>(?>(?&string)\s*:\s*(?&value)))"
        r"(?<array>(?>\[\s*(?>(?&value)(?>\s*,\s*(?&value))*)?\s*\]))"
        r"(?<value>(?>true|false|null|(?&string)|(?&number)|(?&object)|(?&array)))"
        r'(?<string>(?>"(?>\\(?>["\\\/bfnrt]|u[a-fA-F0-9]{4})|[^"\\\0-\x1F\x7F]+)*"))'
        r"(?<number>(?>-?(?>0|[1-9][0-9]*)(?>\.[0-9]+)?(?>[eE][+-]?[0-9]+)?))"
        r")"
        r"(?&json)"
    )
    return json_regex.findall(txt)
