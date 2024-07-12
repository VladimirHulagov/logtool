import os
import pickle

from logtool.scripts.spr100k_mc import full_json, SHCPackageInfoList
from logtool.api.catts import query_by_ppins, CatsTcaList
from logtool.api.facr import get_facr, FACRList

workdir = os.path.dirname(__file__)
tca_json = os.path.join(workdir, "tca.json")
facr_json = os.path.join(workdir, "facr.json")

if __name__ == "__main__":
    facr = get_facr()
    with open(facr_json, "w") as f:
        f.write(facr.model_dump_json(indent=4))

    with open(full_json, "r") as f:
        full = SHCPackageInfoList.model_validate_json(f.read())
    from collections import Counter
    ppins = Counter()
    for r in full.list:
        if r.shc is None:
            continue
        for socket in r.shc.SystemInfo.SocketInfo.values():
            ppins[socket.PPIN] += 1
    # from pprint import pprint
    # pprint(ppins.most_common(20))
    ppins = list(set(int(ppin, 16) for ppin in ppins))
    print(f"Totally {len(ppins)} PPINs")
    batch_sz = 500
    ls = CatsTcaList(list=[])

    def save():
        with open(tca_json, "w") as f:
            f.write(ls.model_dump_json(indent=4, by_alias=True))
    for i in range(0, len(ppins), batch_sz):
        try:
            tcas = query_by_ppins(ppins[i:i+batch_sz])
            ls.list.extend(tcas)
            print(i + batch_sz, len(ls.list))
            save()
        except Exception as e:
            print(repr(e))
            continue
    save()
