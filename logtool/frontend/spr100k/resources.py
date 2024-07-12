from typing import Callable, TypeVar

import streamlit as st

from logtool.scripts.shc_package import GroupedResultByPPINViewList
from logtool.scripts.spr100k_mc import failures_json
from logtool.scripts.spr100k_tca_facr import facr_json, tca_json, FACRList, CatsTcaList
from logtool.scripts.acd_summarize import summary_json, SummarizerResultList

T = TypeVar("T")
V = TypeVar("V")


def make_dict(col: list[T], key: Callable[[T], V]):
    return {key(c): c for c in col}


@st.cache_data
def load_facr():
    with open(facr_json) as f:
        return FACRList.model_validate_json(f.read())


@st.cache_data
def load_facr_dict():
    """Load FACR into a dict indexed by VID 
    """
    facr_dict = make_dict(load_facr().list, lambda fa: fa.alt_code)
    return facr_dict


@st.cache_data
def load_tca():
    with open(tca_json) as f:
        return CatsTcaList.model_validate_json(f.read())


@st.cache_data
def load_tca_dict():
    """Load CATTS TCA into a dict indexed by PPIN
    """
    tca_dict = make_dict(load_tca().list, lambda tca: tca.ppin)
    return tca_dict


@st.cache_data
def load_ppin_view_list():
    with open(failures_json, "r") as f:
        return GroupedResultByPPINViewList.model_validate_json(f.read())


@st.cache_data
def load_acd_list():
    with open(summary_json) as f:
        return SummarizerResultList.model_validate_json(f.read())
