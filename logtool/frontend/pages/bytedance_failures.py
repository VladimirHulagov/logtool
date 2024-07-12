import itertools
import multiprocessing
import io

from collections import Counter

import streamlit as st
import plotly.express as px
import pandas as pd
import tqdm

from logtool.frontend.pages.data import models

st.set_page_config(layout="wide")

# if st.button("Rerun dev"):
#     models.ByteDanceFhmSdkResultList.run_and_save()

if st.button("Reload Data"):
    st.cache_data.clear()


@st.cache_data
def get_results():
    return models.ByteDanceTable.load()

fhm_results = get_results()

def dump_table(t: models.ByteDanceTableEntry):
    return t.full_dump()

def get_table():
    _ = tqdm.tqdm(map(dump_table, fhm_results.list), total=len(fhm_results.list))
    return list(_)

table = get_table()

st.dataframe([{"sn": e.sn, "ppin": e.ppin and hex(e.ppin).upper(), "disposition": e.disposition} for e in fhm_results.list if e._match_strict(("dev", None)) and e.disposition_category.value != "Bystander"])

st.dataframe(map(dump_table, filter(lambda r: r._match_loose(("dev", None)) and not r._match_strict(("dev", None)), fhm_results.list)))

df = pd.DataFrame(table)
if st.toggle("Dev dismatch only"):
    st.dataframe(df[df.apply(lambda row: row["disposition_valid"] and not row["Match dev"], axis=1)], hide_index=True)
else:
    st.dataframe(df, hide_index=True)

match_counter = df.loc[:,[col for col in df.columns if col.startswith("Match ")]].sum()
valid_cnt = sum(1 for d in fhm_results.list if d.disposition_valid)
total_cnt = len(fhm_results.list)
st.text(f"Valid {valid_cnt}")
st.text(f"Total {total_cnt}")
st.text(f"Correct count")
st.dataframe(match_counter)
st.text("Accuracy(%)")
st.dataframe(match_counter / valid_cnt * 100)
# st.text(sum(1 for d in fhm_results.list if "X" in str(d._get_ppins(("dev", None)))))

st.text("Truth table for Dev")
df = pd.DataFrame({"Disposition": r.disposition, "v2.3 category": str(set(r._get_category(("dev", None)))), "Count": 1, "Match": 1 if r.match_result(("dev", None)) else -1 if r.disposition_valid else 0} for r in fhm_results.list)
df = df.groupby(["v2.3 category", "Disposition"]).sum().reset_index()
data = df.pivot(index="v2.3 category", columns="Disposition", values="Count")
style = df.pivot(index="v2.3 category", columns="Disposition", values="Match").map(lambda c: "color:green" if c > 0 else "color:red" if c < 0 else "color:yellow")
st.dataframe(data.style.apply(lambda x: style, axis=None))


