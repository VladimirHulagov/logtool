import multiprocessing

from logtool.model.filemeta import HSDArticle
from logtool.api.hsd import get_article, get_hsdids_by_query, get_internal_attachment, get_external_attachment
from logtool.backend.db import MyDB

import logging
logger = logging.getLogger()
log_formatter = logging.Formatter(
    "[%(asctime)s][%(levelname)s][%(name)s][%(module)s][%(funcName)s] %(message)s")
handler = logging.StreamHandler()
handler.setFormatter(log_formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


def cache_article(db: MyDB, hsdid: int):
    if db.is_article_inserted(hsdid=hsdid):
        return
    try:
        article = get_article(hsdid=hsdid)
        db.try_insert_article(article)
        logger.info("Cached article %d", hsdid)
    except Exception as e:
        logger.exception("Fail to cache article %d", hsdid)


def cache_attachment(db: MyDB, article: HSDArticle):
    # if article.purpose == debug_request
    cached = 0
    error = 0
    exist = 0
    for att in article.attachments:
        try:
            url = f"https://hsdes-api.intel.com/rest/auth/binary/{att.id}"
            if db.is_hsd_attachment_inserted(url):
                exist += 1
                continue
            content = get_internal_attachment(att.id)
            db.try_insert_hsd_attachment(
                hsdid=article.id, url=url, raw_bytes=content)
            logger.info("Cached hsd %s attachement %s", article.id, att.id)
            cached += 1
        except Exception:
            error += 1
            logger.exception(
                "Fail to cache hsd %s attachment %s", article.id, att.id)
            continue
    for url in article.ext_attach_urls:
        try:
            if db.is_hsd_attachment_inserted(url):
                exist += 0
                continue
            content = get_external_attachment(url)
            db.try_insert_hsd_attachment(
                hsdid=article.id, url=url, raw_bytes=content)
            logger.info("Cached hsd %s attachement %s", article.id, url)
            cached += 1
        except Exception:
            error += 1
            logger.exception(
                "Fail to cache hsd %s attachment %s", article.id, url)
            continue
    return (cached, exist, error)


_db = MyDB()


def _cache_article(hsdid: int):
    return cache_article(_db, hsdid)


def _cache_attachments(article: HSDArticle):
    return cache_attachment(_db, article)


if __name__ == "__main__":
    db = MyDB()
    # hsdids = get_hsdids(tenant="server_platf_ae", subject="bug")
    hsdids = get_hsdids_by_query(id=15014059142)
    with multiprocessing.Pool(processes=16) as pool:
        _ = pool.imap_unordered(_cache_article, hsdids)
        list(_)

    # from collections import Counter
    # from pprint import pprint
    # counter = Counter(log.platform for log in db.iterate_articles())
    # pprint(counter)
    # counter = Counter(log.release_affected for log in db.iterate_articles())
    # pprint(counter)

    with multiprocessing.Pool(processes=16) as pool:
        _ = db.iterate_articles()
        _ = filter(lambda a: a.is_spr, _)
        _ = filter(lambda a: a.is_tabb, _)
        # _ = filter(lambda a: a.is_debug_request, _)
        (cached, exist, error) = (0, 0, 0)
        for idx, (c, x, e) in enumerate(pool.imap_unordered(_cache_attachments, _)):
            cached += c
            exist += x
            error += e
            if (idx + 1) % 100 == 0:
                logger.info("Scanned %s articles", (idx + 1))
                logger.info("Cached: %s Existing: %s Error: %s",
                            cached, exist, error)
        logger.info("Cached: %s Existing: %s Error: %s", cached, exist, error)

    with multiprocessing.Pool(processes=16) as pool:
        _ = db.iterate_articles()
        _ = filter(lambda a: a.is_debug_request, _)
        (cached, exist, error) = (0, 0, 0)
        for idx, (c, x, e) in enumerate(pool.imap_unordered(_cache_attachments, _)):
            cached += c
            exist += x
            error += e
            if (idx + 1) % 100 == 0:
                logger.info("Scanned %s articles", (idx + 1))
                logger.info("Cached: %s Existing: %s Error: %s",
                            cached, exist, error)
        logger.info("Cached: %s Existing: %s Error: %s", cached, exist, error)

    # _ = db.iterate_articles()
    # _ = filter(lambda a: a.is_spr, _)
    # _ = filter(lambda a: a.is_tabb, _)
    # _ = filter(lambda a: a.is_spr, _)
    # for idx, article in enumerate(_):
    #     a = db.get_article_with_attachments(article.id)
    #     assert a is not None
    #     logger.info("%s %s %s", a.id, a.title, len(a.attachments))
