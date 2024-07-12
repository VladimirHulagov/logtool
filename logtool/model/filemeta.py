import re
from datetime import datetime

import pydantic


class FileBase(pydantic.BaseModel):
    filename: str
    raw_bytes: bytes


class _HSDInternalAttachmentMeta(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="allow")
    id: int
    title: str

    @property
    def url(self):
        return f"https://hsdes-api.intel.com/rest/auth/binary/{self.id}"


class HSDArticleBase(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="allow")
    id: int
    title: str
    attachments: list[_HSDInternalAttachmentMeta]


class FMToolLogMeta(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="allow")
    sha256code: str
    hdfs_file_path: str
    submitter: str
    deleted_by: str
    logtype: str
    filename: str
    customer: str
    uploaded_time: datetime


class FMToolLog(FMToolLogMeta, FileBase):
    pass


class HSDInternalAttachmentMeta(_HSDInternalAttachmentMeta):
    submitted_by: str
    submitted_date: datetime
    updated_by: str
    updated_date: datetime


class HSDArticle(HSDArticleBase):
    description: str | None
    submitted_by: str
    submitted_date: datetime
    updated_by: str
    updated_date: datetime
    closed_by: str | None
    closed_date: datetime | None
    release_affected: str | None
    component: str | None
    component_affected: str | None
    attachments: list[HSDInternalAttachmentMeta]

    def parse_ext_attach_url(self):
        ext_regex = re.compile(
            r'<a href="(?P<url>http[^"]*)"[^>]*>\[(?P<timestamp>[^]]*)\] (?P<filename>[^<]*)</a>')
        xml: str | None = self.model_extra.get(
            "server_platf_ae.bug.ext_attach_url")
        if not xml:
            return
        for m in ext_regex.finditer(xml):
            gd = m.groupdict()
            yield (gd["filename"], gd["url"])

    @property
    def ext_attach_urls(self):
        for n, url in self.parse_ext_attach_url():
            yield url

    def url_to_name(self, url: str):
        for att in self.attachments:
            if att.url == url:
                return att.title
        for fname, u in self.parse_ext_attach_url():
            if u == url:
                return fname
        assert False

    @property
    def platform(self):
        return self.model_extra.get("bug.platform")

    @property
    def is_debug_request(self):
        return self.model_extra.get("server_platf_ae.bug.article_type") == "debug_request"

    @property
    def is_spr(self):
        return self.release_affected in ["sapphire_rapids", "sapphire_rapids_hbm", "sapphire_rapids_mcc"]

    @property
    def is_tabb(self):
        return self.model_extra.get("server_platf_ae.bug.customer_company") in ["alibaba", "tencent", "bytedance", "inspur", "baidu"]


class HSDArticleWithAttachment(HSDArticle):
    files: list[FileBase]
