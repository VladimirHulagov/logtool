import os
import requests
import pathlib
import typing
from pprint import pprint
import enum
import multiprocessing

import pydantic

from logtool.api import auth


class Metadata(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="allow")
    submitter: str
    logtype: str
    cpu_type: str
    serial_number: str
    filename: str
    customer: str
    sha256code: str


FhmLogTypes = typing.Literal[
    "crashdump",
    "ossyslog",
    "shc",
    "onekeylog",
]


class FHMLogType(enum.Enum):
    Crashdump = "crashdump"
    Ossyslog = "ossyslog"
    Shc = "shc"
    Onekeylog = "onekeylog"


def upload_log(req: auth.FhmRequest, logpath: pathlib.Path, hsdid: int | None = None):
    # TODO: also add hsdid
    with open(logpath, "rb") as f:
        files = {
            "file": (logpath.name, f)
        }
        res = req.request("post", "upload", data=None, files=files)
    return res


def get_loginfo_by_sn(req: auth.FhmRequest, sn: str):
    res = req.request(
        "post",
        "list-page",
        json={
            "query_es_bool": {
                "must": [
                    {
                        "term": {
                            "metadata.serial_number": sn
                        }
                    }
                ]
            }
        }
    )
    results = [Metadata.model_validate(item["metadata"])
               for item in res.json()["data"]["list"]]
    return results


def get_loginfos(
    req: auth.FhmRequest,
    logtype: FhmLogTypes
):
    for page in range(1, 10000):
        res = req.request(
            "post",
            "list-page",
            json={
                "query_es_bool": {
                    "must": [
                        {
                            "term": {
                                "metadata.logtype": logtype
                            }
                        }
                    ]
                },
                "page_size": 100,
                "page_number": page,
            }
        )
        print(page, res.status_code)
        try:
            ls = res.json()["data"]["list"]
            if len(ls) == 0:
                return
            for item in ls:
                yield Metadata.model_validate(item["metadata"])
        except Exception:
            continue
        except KeyboardInterrupt:
            return


def _download_log(req: auth.FhmRequest, meta: Metadata):
    res = req.request(
        "post",
        "download-single",
        json={
            "file_info": {
                **meta.model_dump(),
                "display_logtype": meta.logtype
            }
        }
    )
    fname = res.headers["Content-Disposition"].split("filename=")[1].strip('"')
    return fname, res.content


def download_production_log(meta: Metadata):
    return _download_log(auth.prod_env, meta)


def download_log(sn: str):
    def impl():
        metas = get_loginfo_by_sn(auth.prod_env, sn)
        for meta in metas:
            yield _download_log(auth.prod_env, meta)
    return list(impl())


# def get_logs_meta(logtype: FHMLogType, env: TargetEnv = TargetEnv.dev):
#     url, params, _ = _prepare(env, "list-page")
#     request_body = {
#         "display_logtype": logtype.value,
#         "page_size": 100,
#         "page_number": 1,
#         "query_es_bool": {"must": [{"term": {"metadata.logtype": {"value": logtype.value}}}]}
#     }
#     while True:
#         try:
#             res = requests.post(url, params=params,
#                                 json=request_body, timeout=30)
#             logger.info(f"Got response: {res}")
#         except Exception:
#             logger.exception(f"Fail to send request to {url}")
#             return
#         if res.status_code != 200:
#             return
#         data = res.json()["data"]
#         ls = data["list"]
#         if len(ls) == 0:
#             return
#         for doc in ls:
#             meta = doc["metadata"]
#             yield meta
#         request_body["page_number"] += 1


# def get_log_meta_from_shareid(shareid: str, env: TargetEnv = TargetEnv.dev):
#     url, params, _ = _prepare(env, "shared-uuid/" + shareid)
#     res = requests.get(url, params=params, timeout=30)
#     assert res.status_code == 200
#     return res.json()["data"]


# def cache_fhm_logs(env: TargetEnv = TargetEnv.staging):
#     db = MyDB()
#     mapper = OOOMapper(lambda meta: (
#         meta, download_log(meta, env=env)), threads=16)
#     for t in FHMLogType:
#         metas = get_logs_meta(t, env=env)
#         metas = filter(lambda m: not db.is_log_cached(m["sha256code"]), metas)
#         for meta, content in mapper.map(metas):
#             db.upsert_fmtool_log(meta, content)
#             filename = meta["filename"]
#             logger.info(f"Cached log {filename} of length {len(content)}")


# def download_from_csv():
#     import csv
#     import re
#     from pprint import pprint
#     uuid_regex = re.compile(r"shareinfo/([\w-]+)")
#     work_dir = "/mnt/nvme0n1/shizy/log_analyzer/web/logs"
#     with open("/mnt/nvme0n1/shizy/log_analyzer/web/logs/loglist.csv", encoding="utf-8-sig") as f:
#         reader = csv.DictReader(f, dialect="excel")
#         for row in reader:
#             try:
#                 uuid = uuid_regex.findall(row["Link"])
#                 if not uuid:
#                     logger.info(f"Skipped {row}")
#                     continue
#                 uuid = uuid[0]
#                 logpath = os.path.join(work_dir, row["LogName"] + ".zip")
#                 if os.path.exists(logpath):
#                     continue
#                 content = download_log(get_log_meta_from_shareid(uuid))
#                 with open(logpath, "wb") as f:
#                     f.write(content)
#                 logger.info(f"Downloaded {row}")
#             except Exception:
#                 logger.exception()
#                 pass

def upload_shc_logs():
    import time
    # for log in pathlib.Path("/home/shizy/logs/SHC_INBOUND_LOG").glob("*"):
    #     res = upload_log(log, auth.FhmConfig().configs[auth.FhmTargetEnv.dev])
    #     print(res.status_code)
    #     print(res.text)
    #     time.sleep(30)


def download_bytedance_logs():
    with open(pathlib.Path(__file__).parent.joinpath("bytedance_sns.txt")) as f:
        sns = f.read().splitlines()
    cnt = 0
    for sn in sns:
        print(sn)
        results = get_loginfo_by_sn(auth.prod_env, sn)
        if results:
            cnt += 1
            continue
        for r in results:
            print(r.model_dump_json(indent=4))
            # download_log(auth.prod_env, r)
    print(cnt)


def download_crashdumps():
    infos = get_loginfos(auth.prod_env, FHMLogType.Crashdump)
    with multiprocessing.Pool(32) as pool:
        _ = pool.imap_unordered()
    # print(len(infos))
    # print(infos[0].model_dump_json(indent=4))


if __name__ == "__main__":
    download_crashdumps()
