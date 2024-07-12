import logging
import requests

from requests_ntlm import HttpNtlmAuth

from logtool.model.filemeta import HSDArticleBase
from logtool.api.auth import hsdes_auth, esft_auth

import urllib3
urllib3.disable_warnings()

logger = logging.getLogger()


def _request_get_hsdes_url(uri, params=None, timeout=30):
    # proxy = {'http': '', 'https': ''}
    res = requests.get(
        f"https://hsdes-api.intel.com/rest/auth/{uri}", verify=False, auth=hsdes_auth, params=params, timeout=timeout)
    assert res.status_code == 200
    return res


def _request_post_hsdes_url(uri, params=None, json=None, timeout=30):
    res = requests.post(
        f"https://hsdes-api.intel.com/rest/auth/{uri}", verify=False, auth=hsdes_auth, params=params, json=json, timeout=timeout)
    assert res.status_code == 200
    return res


def get_hsdids(tenant: str = "server_platf_ae", subject: str = "bug"):
    # It seems that HSDes has a limitation of 150K results. While there is a bottleneck at 100K results.
    batch_sz = 100_000
    eql = f"select id WHERE tenant = '{tenant}' AND subject = '{subject}'"
    params = {"start_at": 1, "max_results": batch_sz}
    body = {"eql": eql}
    while True:
        try:
            res = _request_post_hsdes_url(
                f"query/execution/eql", params=params, json=body, timeout=300)
            data = res.json()["data"]
            for meta in data:
                assert "id" in meta
                yield int(meta["id"])
            if len(data) < batch_sz:
                return
            params["start_at"] += batch_sz
        except Exception:
            logger.exception("Fail to query by eql")
            return


def get_hsdids_by_query(id: int = 15014059142):
    batch_sz = 100_000
    params = {"start_at": 1, "max_results": batch_sz}
    while True:
        try:
            res = _request_get_hsdes_url(
                f"query/execution/{id}", params=params, timeout=300)
            data = res.json()["data"]
            for meta in data:
                assert "id" in meta
                yield int(meta["id"])
            if len(data) < batch_sz:
                return
            params["start_at"] += batch_sz
        except Exception:
            logger.exception("Fail to query by eql")
            return


def get_article(hsdid: int):
    try:
        r = _request_get_hsdes_url(f"article/{hsdid}")
        data = r.json()["data"]
        assert len(data) == 1
        data: dict = data[0]
        r = _request_get_hsdes_url(
            f"article/{hsdid}/children", params={"child_subject": "attachment"})
        data["attachments"] = r.json()["data"]
        return HSDArticleBase.model_validate(data)
    except Exception:
        logger.exception(f"Fail to retrieve article {hsdid}")
        raise


def get_internal_attachment(id: int) -> bytes:
    r = _request_get_hsdes_url(f"binary/{id}", timeout=120)
    return r.content


def get_external_attachment(url: str) -> bytes:
    r = requests.get(url, verify=False, auth=esft_auth,
                     allow_redirects=True, timeout=120)
    assert r.status_code == 200
    return r.content


if __name__ == "__main__":
    # for idx, hsdid in enumerate(get_hsdids_by_query()):
    #     print(idx, hsdid)
    #     if idx > 10:
    #         break
    content = get_external_attachment(
        'https://esft-int.intel.com/sftservices/download/HSDES_SFT/?FileName=QTW2321-00174_debug%20bios.zip&AppFileID=09b37319-7491-47e0-a4c5-14837415ec57&AppData=22018681860')
    print(content[:100])
    import os
    hsdids = list(get_hsdids_by_query())
    for dir in os.listdir("/home/shizy/log_analyzer/tasks/shclogs"):
        hsdid = int(dir)
        if hsdid not in hsdids:
            print(hsdid)
        else:
            print("XX")
