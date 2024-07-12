from datetime import datetime, timezone, timedelta

import streamlit as st

from logtool.frontend.spr100k.resources import load_facr_dict, load_ppin_view_list, load_tca_dict


st.set_page_config(layout="wide")


facr_dict = load_facr_dict()
tca_dict = load_tca_dict()
ppin_view_list = load_ppin_view_list()

_ = ppin_view_list.list
if st.toggle("Must contain mca error"):
    _ = filter(lambda view: view.mca_failed, _)
if st.toggle("Must contain shc error"):
    _ = filter(lambda view: view.shc_failed, _)
_ = list(_)

results = map(lambda view: view.model_dump(exclude="packages"), _)
results = list(results)
for r in results:
    tca = tca_dict.get(r.get("ppin"))
    vid = tca.vid if tca else None
    r["vid"] = vid
    r["ppin"] = hex(r["ppin"])
    r.update(facr_dict.get(vid, {}))
    if tca:
        r.update(tca.model_dump(exclude=["ppin"]))

st.subheader(f"Selected {len(results)}/{len(ppin_view_list.list)} PPINs")
st.dataframe(results)

ppin = st.text_input(label="Input ppin for details", value=hex(_[0].ppin))
try:
    ppin = int(ppin, 16)
except:
    st.error("Invalid ppin")
    st.stop()

ppin_view = None
for r in _:
    if r.ppin == ppin:
        ppin_view = r
        break
if ppin_view is None:
    st.warning("PPIN unavailable")
    st.stop()

res = [r for r in results if r["ppin"] == hex(ppin)]
# assert len(res) == 1
st.dataframe(res)

res = []
for log in ppin_view.packages:
    st.write(log.filename)
    tests = [t.model_dump() for t in log.shc.failed_tests]
    for t in tests:
        t["StartTime"] = t["StartTime"].replace(
            tzinfo=timezone(offset=timedelta(hours=8)))
        t["time"] = t["StartTime"]
        t["EndTime"] = t["EndTime"].replace(
            tzinfo=timezone(offset=timedelta(hours=8)))
    res.extend(tests)

    def to_hex(mc, field):
        mc[field] = hex(mc[field]) if mc[field] is not None else None
    machine_checks = [mca.model_dump() for mca in log.mcas]
    for mc in machine_checks:
        to_hex(mc, "status")
        to_hex(mc, "misc")
        to_hex(mc, "address")
    res.extend(machine_checks)
res.sort(key=lambda d: d["time"])
st.dataframe(res)
