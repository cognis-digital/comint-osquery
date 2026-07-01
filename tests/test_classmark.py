"""Tests for the CAPCO-shape ClassificationBanner (placeholder validator)."""
import pytest

from cognis_mil.classmark import ClassificationBanner, VALID_LEVELS


def test_placeholder_is_unclassified_public():
    b = ClassificationBanner.placeholder()
    assert b.level == "UNCLASSIFIED"
    assert "FOR PUBLIC RELEASE" in b.render()


def test_default_level_valid():
    ok, errs = ClassificationBanner().validate()
    assert ok
    assert errs == []


@pytest.mark.parametrize("level", VALID_LEVELS)
def test_all_valid_levels_accepted(level):
    ok, _ = ClassificationBanner(level=level).validate()
    assert ok


def test_invalid_level_rejected():
    ok, errs = ClassificationBanner(level="ULTRA SECRET").validate()
    assert not ok
    assert any("Invalid base level" in e for e in errs)


def test_unclassified_with_sci_rejected():
    ok, errs = ClassificationBanner(level="UNCLASSIFIED", sci=["SI"]).validate()
    assert not ok
    assert any("SCI" in e for e in errs)


def test_unclassified_with_sap_rejected():
    ok, errs = ClassificationBanner(level="UNCLASSIFIED", sap=["PROG"]).validate()
    assert not ok


def test_render_plain_level():
    assert ClassificationBanner(level="SECRET").render() == "SECRET"


def test_render_with_sci_compartment():
    line = ClassificationBanner(level="TOP SECRET", sci=["SI", "TK"]).render()
    assert line == "TOP SECRET//SI/TK"


def test_render_with_sap():
    line = ClassificationBanner(level="SECRET", sap=["ALPHA"]).render()
    assert "SAR-ALPHA" in line


def test_render_with_dissem():
    line = ClassificationBanner(level="SECRET", dissem=["NOFORN"]).render()
    assert line == "SECRET//NOFORN"


def test_render_with_nonic():
    line = ClassificationBanner(level="UNCLASSIFIED", nonic=["FOUO"]).render()
    assert "FOUO" in line


def test_render_combined():
    b = ClassificationBanner(level="TOP SECRET", sci=["SI"], dissem=["NOFORN"])
    line = b.render()
    assert line.startswith("TOP SECRET//SI//")
    assert "NOFORN" in line


def test_render_is_cp1252_safe():
    ClassificationBanner(level="SECRET", sci=["SI"], dissem=["NOFORN"]).render().encode("cp1252")


def test_higher_level_no_markings_is_still_valid():
    # A smell, not an error — SECRET with no compartments is permitted shape.
    ok, _ = ClassificationBanner(level="SECRET").validate()
    assert ok
