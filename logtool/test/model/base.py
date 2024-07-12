import pytest
from logtool.model.base import EventSeverity


def test_event_severity_ordering():
    assert EventSeverity.critical > EventSeverity.error
    assert EventSeverity.error > EventSeverity.warning
    assert EventSeverity.warning > EventSeverity.info
    assert EventSeverity.info > EventSeverity.verbose
    assert EventSeverity.critical > EventSeverity.verbose

    assert EventSeverity.critical == EventSeverity.critical
    assert EventSeverity.error == EventSeverity.error
    assert EventSeverity.warning == EventSeverity.warning
    assert EventSeverity.info == EventSeverity.info
    assert EventSeverity.verbose == EventSeverity.verbose

    assert EventSeverity.critical >= EventSeverity.critical
    assert EventSeverity.verbose < EventSeverity.critical
