def fmtool_download_log(hdfs_path: str):
    import requests
    url = "http://10.239.173.54:8280/fleet-dev/fhmtool/pages/download"
    res = requests.get(url, params={"path": hdfs_path})
    assert res.status_code == 200
    return res.content
