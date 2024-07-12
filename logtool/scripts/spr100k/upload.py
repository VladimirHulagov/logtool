import pathlib
import multiprocessing
import traceback

import tqdm
import pydantic

from logtool.api.fhm import upload_log, auth
from logtool.model.logs.shc import ShcParser, ShcReport
from logtool.utils.file import ArchiveFile


class UploadedLogs(pydantic.BaseModel):
    failed_logs: list[str]
    uploaded_logs: list[str]


def filter_shc_failure(log: pathlib.Path):
    # print(f"Checking log {log.name}")
    try:
        with ArchiveFile(log) as archive:
            for m in archive.getmembers():
                if m.name.endswith("report.json"):
                    report = archive.extract(m).read().decode()
                    shc: ShcReport = ShcParser().parse(report)
                    if any("PASSED" not in r for r in shc.SHCSummary.SHCOverallResults):
                        return log
    except Exception:
        traceback.print_exc()
        pass
    return None


if __name__ == "__main__":
    save_path = pathlib.Path(__file__).parent.joinpath("uploaded.json")
    uploaded = UploadedLogs(failed_logs=[], uploaded_logs=[])

    def save():
        with open(save_path, "w") as f:
            f.write(uploaded.model_dump_json(indent=4))
    try:
        with open(save_path) as f:
            uploaded = UploadedLogs.model_validate_json(f.read())
    except Exception:
        save()
    logsdir = pathlib.Path("/home/shizy/logs/SHC_INBOUND_LOG")
    with multiprocessing.Pool(processes=64) as pool:
        _ = logsdir.glob("*")
        logs = list(_)
        _ = tqdm.tqdm(pool.imap_unordered(filter_shc_failure, logs), total=len(logs))
        _ = filter(None, _)
        logs = sorted(_, key=lambda p: p.name)
        uploaded.failed_logs = [log.name for log in logs]
    for logname in uploaded.failed_logs:
        log = logsdir.joinpath(logname)
        print(f"Found log with error: {log.name}")
        if log.name in uploaded.uploaded_logs:
            continue
        res = upload_log(auth.prod_env, log)
        print(res.status_code)
        print(res.text)
        print(res.request.url)
        if res.status_code == 200:
            uploaded.uploaded_logs.append(log.name)
        save()
