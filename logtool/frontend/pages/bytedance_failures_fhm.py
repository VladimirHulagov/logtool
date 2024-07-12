import itertools
import multiprocessing

from collections import Counter

import streamlit as st
import plotly.express as px
import pandas as pd
import tqdm

from logtool.frontend.pages.data import models

st.set_page_config(layout="wide")

@st.cache_data
def get_results():
    return models.ByteDanceSimpleTable.load()

fhm_results = get_results()

def get_table():
    _ = tqdm.tqdm(map(lambda d: d.table_dump(), fhm_results.list), total=len(fhm_results.list))
    return list(_)

table = get_table()
df = pd.DataFrame(table)
st.dataframe(df, hide_index=True)

match_counter = df.iloc[:,-4:].sum()
valid_cnt = sum(1 for d in fhm_results.list if d.disposition_valid)
total_cnt = len(fhm_results.list)
st.text(f"Valid {valid_cnt}")
st.text(f"Total {total_cnt}")
st.text(f"Correct count")
st.dataframe(match_counter)
st.text("Accuracy(%)")
st.dataframe(match_counter / valid_cnt * 100)

# st.text("Truth table for latest SDK")
# df = pd.DataFrame({"Disposition": r.disposition, "v2.3 category": str(set(r._get_category)), "Count": 1, "Match": 1 if r.v3_match_loose(r.v2p3_results) else -1 if r.disposition_valid else 0} for r in fhm_results.list)
# df = df.groupby(["v2.3 category", "Disposition"]).sum().reset_index()
# data = df.pivot(index="v2.3 category", columns="Disposition", values="Count")
# style = df.pivot(index="v2.3 category", columns="Disposition", values="Match").map(lambda c: "color:green" if c > 0 else "color:red" if c < 0 else "color:yellow")
# st.dataframe(data.style.apply(lambda x: style, axis=None))

# st.dataframe([row for row in table if not row["match(v3)"]], hide_index=True)
