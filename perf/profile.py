from cProfile import Profile
from pstats import SortKey, Stats


def profile(func):
    def _func(*args, **kwds):
        with Profile() as profile:
            res = None
            try:
                res = func(*args, **kwds)
            except KeyboardInterrupt:
                pass
            finally:
                (
                    Stats(profile)
                    .strip_dirs()
                    .sort_stats(SortKey.CUMULATIVE)
                    .print_callees(20)
                )
                return res
    return _func
