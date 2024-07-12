from collections import Counter
from datetime import datetime

import plotly.express as px

import streamlit as st
import pandas as pd

from logtool.api.catts import CatsTca
from logtool.scripts.spr100k_tca_facr import CatsTcaList, tca_json
from logtool.frontend.spr100k.resources import load_tca_dict, load_ppin_view_list

ppin_views = load_ppin_view_list()
tca_dict = load_tca_dict()

_ = ppin_views.list
if st.toggle("Must contain mca error"):
    _ = filter(lambda view: view.mca_failed, _)
if st.toggle("Must contain shc error"):
    _ = filter(lambda view: view.shc_failed, _)


ppins = list(tca_dict.keys())


def calc_stat(attr: str):
    def _getattr(ppin):
        if ppin not in ppins:
            return None
        return getattr(tca_dict[ppin], attr)
    all_counter = Counter(_getattr(tca.ppin) for tca in tca_dict.values())
    err_counter = Counter(_getattr(view.ppin) for view in ppin_views.list)
    values = [err_counter.get(ppin, 0) for ppin in all_counter]
    df = pd.DataFrame(
        {attr: all_counter.keys(), "All": all_counter.values(), "Filtered": values})
    df.set_index(attr)
    df.insert(len(df.columns), "Ratio", [
              e/a for (a, e) in zip(all_counter.values(), values)])
    return df


for attr in ["batch", "material_id", "tray_box_id"]:
    st.subheader(attr)
    df = calc_stat(attr)
    st.dataframe(df, hide_index=True)
# st.plotly_chart(px.pie(batches))
