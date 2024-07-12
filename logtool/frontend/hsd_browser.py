import re

import streamlit as st

# from logtool.model.hsd import HSDArticleView
from logtool.backend.db import MyDB

st.set_page_config(layout="wide")

db = MyDB()

text = st.text_input("Text containing HSDES ids")
hsdid_regex = re.compile(r"\d{5,}")

hsdids = hsdid_regex.findall(text)
st.write(hsdids)
_ = map(lambda hsdid: db.get_article(hsdid), hsdids)
_ = filter(None, _)
# _ = map(lambda a: HSDArticleView(**a.model_dump()), _)
articles = list(_)

fields = [
    "id",
    "title",
    "status",
    "bug.platform",
    "server_platf_ae.bug.customer_company",
    "submitted_date",
    "bug.fix_description",
    "link",
    "release",
    "description",
    "server_plaft_ae.bug.cpu",
    "server_plaft_ae.bug.conclusion",
]
# print(articles[0].model_dump_json(indent=4))
_ = map(lambda a: a.model_dump(include=fields), articles)
_ = list(_)
for a, article in zip(_, articles):
    id = a["id"]
    a["link"] = f"https://hsdes.intel.com/appstore/article/#/{id}"
    for f in fields:
        if f in a:
            continue
        a[f] = article.model_extra.get(f)

st.dataframe(
    _, column_order=fields,
    column_config={
        "id": st.column_config.TextColumn(),
        "link": st.column_config.LinkColumn()
    }
)
