import tempfile
import shutil
import pathlib
import hashlib
import multiprocessing
import datetime
import itertools
from collections import Counter

import pydantic
import tqdm
import streamlit as st

from logtool.frontend.pages.data import models

st.set_page_config(layout="wide")


@st.cache_data
def get_results():
    return models.ByteDanceLogsList.load_logs()

if "fhm_results" not in st.session_state:
    st.session_state.fhm_results = get_results()
fhm_results = st.session_state.fhm_results

def get_idl(log: pathlib.Path):
    def impl():
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = pathlib.Path(tmpdir)
            try:
                shutil.unpack_archive(log, tmpdir)
            except Exception:
                pass
            for f in tmpdir.rglob("*"):
                try:
                    shutil.unpack_archive(f, f.parent.joinpath(f.name.split(".")[0]))
                except Exception:
                    continue
            _ = tmpdir.rglob("idl.log")
            # _ = filter(lambda f: f.is_file(), _)
            for p in _:
                try:
                    with open(p) as f:
                        yield p, f.read()
                except Exception:
                    continue
    return list(impl())

@st.cache_data(persist="disk")
def get_idl_logs():
    with multiprocessing.Pool(32) as pool:
        logs = list(log for res in fhm_results for log in res.logpaths)
        res = tqdm.tqdm(pool.imap_unordered(get_idl, logs), total=len(logs))
        return [log for r in list(res) for log in r]

if "idl_logs" not in st.session_state:
    st.session_state.idl_logs = get_idl_logs()
idl_logs = st.session_state.idl_logs
# idl_logs = get_idl_logs()

log = st.selectbox("Select idl.log", idl_logs, format_func=lambda tup: tup[0])
if not log:
    st.stop()
c = st.container(height=1000)
c.text(log[1])

# @st.cache_data(persist="disk")
def get_parsed_logs():
    def parse_log(log: str):
        _ = map(models.IdlEntry.parse_line, log.splitlines())
        return list(_)
    _ = idl_logs
    _ = map(lambda log: log[1], _)
    _ = map(parse_log, _)
    _ = itertools.chain.from_iterable(_)
    return list(_)

details = set()
entries: list[models.IdlEntry] = []
for e in get_parsed_logs():
    if e.detail not in details:
        details.add(e.detail)
        entries.append(e)

# st.write(len(entries))
st.dataframe((e.model_dump() for e in entries if not e.error_cat))
st.dataframe((e.model_dump() for e in entries if e.error_cat))

def dump_idl(t: models.TrackingListWithLog):
    try:
        _ = t.idl_keyevents
        _ = map(lambda e: e.model_dump_json(), _)
        return list(_)
    except Exception:
        import traceback
        traceback.print_exc()
        return []

with multiprocessing.Pool(32) as pool:
    trackings = models.fetch_bytedance_logs()
    _ = tqdm.tqdm(pool.imap_unordered(dump_idl, trackings), total=len(trackings))
    res = list(_)
    for r in res:
        st.dataframe(r)

# counter1 = Counter(e.detail for e in entries if not e.error_cat)
# counter2 = Counter(e.detail for e in entries if e.error_cat)
# for counter in [counter1, counter2]:
#     st.write(len(counter))
#     st.dataframe(counter, use_container_width=True)
# st.write(str(list(Counter(e.detail for e in entries).keys())))
