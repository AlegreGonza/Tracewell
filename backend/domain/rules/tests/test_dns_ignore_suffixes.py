"""ignore_suffixes del detector dns_suspicious."""
import pytest

from backend.domain.rules.engine import DnsSuspiciousDetector, RuleError, evaluate, load_rules
from backend.domain.rules.tests.test_engine import REAL_RULES, base, dns_pkt, mk, write_rule  # noqa: F401

LONG = "a" * 50  # label largo: alertaría sin ignore
WPS = "clb-k8s-us-prod-msgpush-01-1431806435.us-west-2.elb.amazonaws.com"


def alerts(mk, suffixes, name, **kw):
    return evaluate([mk("dns_suspicious", ignore_suffixes=suffixes)], [dns_pkt(1, name, **kw)])


def _bare(params):
    det = DnsSuspiciousDetector.__new__(DnsSuspiciousDetector)
    det.p = params
    return det


def test_exact_domain_ignored(mk):
    assert alerts(mk, ["evil.com"], "evil.com") == []


def test_subdomain_ignored(mk):
    assert alerts(mk, ["evil.com"], f"{LONG}.evil.com") == []
    assert alerts(mk, ["evil.com"], f"{LONG}.a.b.evil.com") == []


def test_not_mere_string_suffix(mk):
    assert len(alerts(mk, ["elb.amazonaws.com"], f"{LONG}.notelb.amazonaws.com")) == 1


def test_outside_list_still_alerts_high_entropy(mk):
    name = "q8x2kz7vb1mw4jr9tc5yh3ne.example.com"
    assert len(alerts(mk, ["elb.amazonaws.com"], name)) == 1


def test_case_insensitive(mk):
    assert alerts(mk, ["ELB.AmazonAWS.com"], f"{LONG}.Elb.Amazonaws.COM") == []


def test_trailing_dot_and_dotted_config(mk):
    assert alerts(mk, [".evil.com."], f"{LONG}.evil.com") == []
    det = _bare({"ignore_suffixes": ["evil.com"]})
    assert det._is_ignored("x.evil.com.") and det._is_ignored("evil.com.")


def test_is_ignored_handbuilt_params_without_key():
    assert _bare({})._is_ignored("evil.com") is False


def test_empty_list_ignores_nothing(mk):
    assert len(alerts(mk, [], f"{LONG}.elb.amazonaws.com")) == 1


def test_shipped_rule_wps_case_no_alert():
    rule = next(r for r in load_rules(REAL_RULES) if r.id == "dns_suspicious")
    assert evaluate([rule], [dns_pkt(1, WPS)]) == []
    assert len(evaluate([rule], [dns_pkt(1, "q8x2kz7vb1mw4jr9tc5yh3ne.example.com")])) == 1


@pytest.mark.parametrize("bad", [
    "elb.amazonaws.com", None, 5, {"a": 1}, [""], ["  "], ["."], [5], [None], ["a b.com"], ["a\tb"], [["x"]],
])
def test_invalid_values_raise_ruleerror(tmp_path, bad):
    f = write_rule(tmp_path, base("dns_suspicious", params={"ignore_suffixes": bad}), "dnsbad.yaml")
    with pytest.raises(RuleError, match="dnsbad.yaml"):
        load_rules(f)


def test_normalized_on_load(tmp_path):
    f = write_rule(tmp_path, base("dns_suspicious", params={"ignore_suffixes": [".Foo.COM.", "bar.org"]}))
    assert load_rules(f)[0].params["ignore_suffixes"] == ["foo.com", "bar.org"]
