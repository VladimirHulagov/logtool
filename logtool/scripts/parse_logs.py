import multiprocessing
import pathlib
import re
import typing
import hashlib


from logtool.model.interface import ISerializableParsedLog, Tag, TagType, FileMeta, SerializedException
from logtool.model.logs.azure_sel import AzureSelParser
from logtool.model.logs.summary import AcdSummarizer
from logtool.model.logs.shc import ShcParser
from logtool.model.logs.fhm import FmtoolSyslogParser, FmtoolAcdParser
from logtool.model.logs.syslog import SyslogParser
from logtool.utils.file import ArchiveFile, ArchiveInfo
from logtool.backend.tmp_db import MyDB
from logtool.backend.db import MyDB as FhmDb, FMToolLog


parsers = {
    ShcParser: [re.compile(r"^report\.json$")],
    SyslogParser: [re.compile(r"^sys[^.]+\.log$")],
    # AcdSummarizer: [re.compile(r"^AcdDump[^.]+\.json$")],
    # AzureSelParser: [re.compile(r"^.*SEL.*$")],
    AcdSummarizer: [re.compile(r"^[^.]+\.json$")],
    FmtoolAcdParser: [re.compile(r"^[^.]+\.json$")],
    AzureSelParser: [re.compile(r"^SEL[^.]+\.txt$")],
    FmtoolSyslogParser: [re.compile(r"^sys[^.]+\.log$")],
}


def try_get_uuid_from_path(path: pathlib.Path):
    uuid = path.parent.name
    return uuid


def try_get_sn_from_topology_xml(content: str):
    from xml.dom import minidom

    def getElementByAttribute(node: minidom.Element, tag: str, attribute: str, value: str):
        childs = node.getElementsByTagName(tag)
        childs = [c for c in childs if c.getAttribute(attribute) == value]
        assert (len(childs) == 1)
        return childs[0]
    doc = minidom.parseString(content)
    topology = doc.getElementsByTagName("topology")[0]
    machine = getElementByAttribute(topology, "object", "type", "Machine")
    serial = getElementByAttribute(machine, "info", "name", "DMIProductSerial")
    return serial.getAttribute("value")


def shc_archives():
    logsdir = "/home/shizy/logs/SHC_INBOUND_LOG"
    for log in pathlib.Path(logsdir).glob("*.xz"):
        yield log


def azure_archives():
    logs_dir = "/home/shizy/logs/FleetHealthManagement/Raw/Azure"
    for log in pathlib.Path(logs_dir).glob("Gen9*.zip"):
        yield log
    for log in pathlib.Path(logs_dir).glob("Gen 9*.zip"):
        yield log
    for log in pathlib.Path(logs_dir).glob("Gen8 CPU*.zip"):
        yield log


def kuaishou_archives():
    log = "/home/shizy/logs/FleetHealthManagement/Raw/Kuaishou/intel_log_0526-0705.tar.gz"
    yield pathlib.Path(log)


ArchiveMember = tuple[pathlib.Path, ArchiveInfo]


def get_logs(paths: typing.Iterable[pathlib.Path]):
    for archive_path in paths:
        with ArchiveFile(archive_path) as a:
            members = a.getmembers()
        for m in members:
            if m.isfile():
                yield archive_path, m


def get_fhm_syslogs():
    db = FhmDb()
    _ = db.iterate_fmtool_logs()
    _ = filter(lambda log: log.logtype == "ossyslog", _)
    _ = filter(lambda log: "fmtool" not in log.submitter, _)
    for log in _:
        yield log


def parse_fhm_syslog(log: FMToolLog):
    meta = FileMeta(name=log.filename, sha256=log.sha256code)
    sn_regex = re.compile(r"sys_([^_]*)_\d+.*")
    sns = sn_regex.findall(log.filename)
    assert len(sns) <= 1
    if not sns:
        # TODO: handle fake syslogs
        return None
    tag = Tag(type=TagType.SN, value=sns[0])
    logs: list[ISerializableParsedLog] = []
    for parser in [
        SyslogParser,
        FmtoolSyslogParser,
    ]:
        try:
            res: ISerializableParsedLog = parser().parse(log.raw_bytes)
        except Exception as e:
            res = SerializedException.from_exception(e)
        logs.append(res)
    return meta, [tag], logs


def parse_log(params: ArchiveMember):
    path, info = params
    name = pathlib.Path(info.name).name
    with ArchiveFile(path) as a:
        f = a.extract(info)
        assert f is not None
        content = f.read()
    sha256 = hashlib.sha256(content).hexdigest()
    meta = FileMeta(name=name, sha256=sha256)
    tags = get_tags(params)
    logs: list[ISerializableParsedLog] = []
    for parser, patterns in parsers.items():
        if not any(p.fullmatch(name) for p in patterns):
            continue
        p = parser()
        if not p.check(content):
            continue
        try:
            log = p.parse(content)
        except Exception as e:
            log = SerializedException.from_exception(e)
        assert isinstance(log, (ISerializableParsedLog, SerializedException))
        logs.append(log)
    if logs:
        return meta, tags, logs
    return None


def get_shc_log_sn(params: ArchiveMember):
    path, _ = params
    with ArchiveFile(path) as a:
        for info in a.getmembers():
            name = pathlib.Path(info.name).name
            if name == "topology.xml":
                content = a.extract(info)
                assert content
                sn = try_get_sn_from_topology_xml(content.read().decode())
                return Tag(type=TagType.SN, value=sn)
    return None


def get_kuaishou_sn(params: ArchiveMember):
    path, member = params
    sn_regex = re.compile(r"sys_([^_]*)_\d+.*")
    match = sn_regex.findall(member.name)
    if len(match) == 1:
        if not match[0]:
            return None
        return Tag(type=TagType.SN, value=match[0])
    elif not match:
        return None
    else:
        assert False, member.name


def get_uuid(params: ArchiveMember):
    path, info = params
    uuid = pathlib.Path(info.name).parent.name
    pattern = re.compile(r"^[0-9a-fA-F-]{36}$")
    if pattern.fullmatch(uuid):
        return Tag(type=TagType.UUID, value=uuid)
    return None


def get_tags(params: ArchiveMember):
    return list(filter(None, map(
        lambda f: f(params),
        [
            get_shc_log_sn,
            get_uuid,
            get_kuaishou_sn,
        ]
    )))


def my_map(func, params):
    if __debug__:
        for p in params:
            yield func(p)
        return
    with multiprocessing.Pool(processes=40) as pool:
        _ = pool.imap_unordered(func, params)
        for res in _:
            yield res
        return


if __name__ == "__main__":
    db = MyDB()
    import os
    # os.remove(pathlib.Path(db.db_file))
    db = MyDB()
    for a in [
        # azure_archives(),
        shc_archives(),
        # kuaishou_archives,
    ]:
        _ = get_logs(a)
        # _ = filter(lambda log: "SEL(4480792f-5b25-8634-5655-7e1ba36f7faf).txt" in log[1].name, _)
        # _ = [log for idx, log in enumerate(_) if idx < 10]
        _ = my_map(parse_log, _)
        _ = filter(None, _)
        for tup in _:
            meta, tags, logs = tup
            assert tags
            print("XXXXXXXXXXXXXXXXXXXXXXXXXX", meta.name)
            for res in logs:
                print(res._type, res.signature, res.description)
                db.upsert_parsed(meta, res)
                # for e in res.key_events:
                #     print(e._time, e._type, e.description)
            for tag in tags:
                print(tag)
                db.try_add_tag(meta, tag)
                db.try_add_tag(meta, Tag(type=TagType.Source, value="Spr100k"))
    exit()

    _ = get_fhm_syslogs()
    _ = my_map(parse_fhm_syslog, _)
    _ = filter(None, _)
    for tup in _:
        meta, tags, logs = tup
        print("XXXXXXXXXXXXXXXXXXXXXXXXXX", meta.name)
        for res in logs:
            print(res._type, res.signature, res.description)
            db.upsert_parsed(meta, res)
            # for e in res.key_events:
            #     print(e._time, e._type, e.description)
        for tag in tags:
            print(tag)
            db.try_add_tag(meta, tag)
