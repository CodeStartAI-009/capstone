"""Feature extraction: schema order, definitions, validation and edge cases."""
import math

import pytest

from ml.feature_extractor import (FeatureValidationError, compute_features, extract_features, model_input,
                                  validate_vector)
from ml.feature_schema import (EXCLUDED_FEATURES, FEATURE_COUNT, FEATURE_DESCRIPTIONS, FEATURE_NAMES,
                               FEATURE_ORDER, FEATURE_RANGES, FEATURE_SCHEMA, FEATURE_TYPES)
from ml.url_utils import InvalidURLError

TABLE = {"com": 0.5229071, "uk": 0.028555, "dev": 0.0009613}


def feats(url):
    return compute_features(url, TABLE)


# --- schema ------------------------------------------------------------------

def test_schema_is_consistent():
    assert FEATURE_COUNT == 17 == len(FEATURE_NAMES) == len(set(FEATURE_NAMES))
    assert tuple(FEATURE_NAMES) == FEATURE_ORDER
    assert set(FEATURE_TYPES) == set(FEATURE_RANGES) == set(FEATURE_DESCRIPTIONS) == set(FEATURE_NAMES)
    assert [s["name"] for s in FEATURE_SCHEMA] == FEATURE_NAMES


def test_leaky_and_irreproducible_features_are_excluded():
    assert "URLSimilarityIndex" in EXCLUDED_FEATURES and "URLSimilarityIndex" not in FEATURE_NAMES
    assert "URLCharProb" not in FEATURE_NAMES
    assert not set(EXCLUDED_FEATURES) & set(FEATURE_NAMES)


def test_vector_follows_schema_order_exactly():
    out = extract_features("https://login.example.com/path?a=1", tld_table=TABLE)
    assert out["feature_names"] == FEATURE_NAMES
    assert len(out["vector"]) == FEATURE_COUNT
    assert out["vector"] == [out["features"][name] for name in FEATURE_NAMES]


def test_types_and_ranges_are_valid_for_varied_urls():
    for url in ["https://www.example.com", "http://1.2.3.4/x", "https://a.b.c.d.example.co.uk:8443/p?q=1&r=%20",
                "example.com", "https://xn--80ak6aa92e.com", "https://[2001:db8::1]/"]:
        vector = extract_features(url, tld_table=TABLE)["vector"]
        validate_vector(vector)
        for name, value in zip(FEATURE_NAMES, vector):
            assert isinstance(value, int if FEATURE_TYPES[name] == "int" else (int, float)), name
            assert math.isfinite(value)


# --- definitions (values checked by hand against stored PhiUSIIL rows) ---------

def test_definitions_match_dataset_row():
    # test.csv row: https://sh5sss.webwave.dev/ (offset-0 batch, so stored values apply to the full URL)
    f = feats("https://sh5sss.webwave.dev/")
    assert f["URLLength"] == 27
    assert f["DomainLength"] == 18
    assert f["TLDLength"] == 3
    assert f["NoOfSubDomain"] == 1
    assert f["NoOfLettersInURL"] == 15 and f["LetterRatioInURL"] == 0.556
    assert f["NoOfDegitsInURL"] == 1 and f["DegitRatioInURL"] == 0.037
    assert f["NoOfOtherSpecialCharsInURL"] == 3 and f["SpacialCharRatioInURL"] == 0.111
    assert f["CharContinuationRate"] == pytest.approx(0.642857143, abs=1e-6)
    assert f["TLDLegitimateProb"] == 0.0009613
    assert f["IsHTTPS"] == 1 and f["IsDomainIP"] == 0


def test_percent_count_uses_dataset_semantics():
    # The dataset column NoOfAmpersandInURL counts '%', not '&' (100% parity).
    f = feats("https://servicemail8.godaddysites.com/at%26t-mail")
    assert f["NoOfAmpersandInURL"] == 1
    assert feats("https://x.com/?a=1&b=2")["NoOfAmpersandInURL"] == 0


def test_ip_address_url():
    assert feats("http://192.168.10.5/login")["IsDomainIP"] == 1
    assert feats("http://38.209.148.132.host.secureserver.net/")["IsDomainIP"] == 1
    assert feats("https://www.example.com")["IsDomainIP"] == 0


def test_https_and_http():
    assert feats("https://example.com")["IsHTTPS"] == 1
    assert feats("http://example.com")["IsHTTPS"] == 0
    # dataset definition: 'https' anywhere in the URL
    assert feats("http://evil.com/?next=https://bank.com")["IsHTTPS"] == 1


def test_subdomains():
    assert feats("https://example.com")["NoOfSubDomain"] == 0
    assert feats("https://www.example.com")["NoOfSubDomain"] == 1
    assert feats("https://a.b.c.example.com")["NoOfSubDomain"] == 3


def test_long_url_and_special_characters():
    url = "https://example.com/" + "a1-_" * 300 + "?x=1&y=2&z=%41"
    f = feats(url)
    assert f["URLLength"] == len(url)
    assert f["NoOfEqualsInURL"] == 3 and f["NoOfQMarkInURL"] == 1 and f["NoOfAmpersandInURL"] == 1
    assert 0.0 <= f["SpacialCharRatioInURL"] <= 1.0


def test_unknown_tld_uses_documented_fallback():
    assert feats("https://example.zzzz")["TLDLegitimateProb"] == 0.0


# --- model input view --------------------------------------------------------------

def test_host_view_drops_path_scheme_userinfo_and_www():
    assert model_input("http://user@www.Example.com:8080/a/b?c=d", "host") == "https://www.Example.com:8080"
    assert model_input("https://github.com/pallets/flask", "host") == "https://www.github.com"
    assert model_input("https://github.com/x", "full") == "https://github.com/x"
    with pytest.raises(ValueError):
        model_input("https://a.com", "other")


def test_host_view_makes_deep_links_equal_to_their_homepage():
    a = extract_features("https://github.com/pallets/flask", tld_table=TABLE)["vector"]
    b = extract_features("https://www.github.com", tld_table=TABLE)["vector"]
    assert a == b


# --- validation ----------------------------------------------------------------

@pytest.mark.parametrize("bad", ["", "   ", "http://", "https://exa mple.com", "javascript:alert(1)",
                                 "ftp://example.com", "http://-bad-.com", "http://example.com:99999", None, 42])
def test_malformed_input_is_rejected(bad):
    with pytest.raises(InvalidURLError):
        extract_features(bad, tld_table=TABLE)


def test_validate_vector_rejects_wrong_shape_type_and_range():
    good = extract_features("https://example.com", tld_table=TABLE)["vector"]
    with pytest.raises(FeatureValidationError):
        validate_vector(good[:-1])
    with pytest.raises(FeatureValidationError):
        validate_vector(good[:-1] + ["1"])
    with pytest.raises(FeatureValidationError):
        validate_vector(good[:-1] + [2])  # IsHTTPS must be 0/1
    with pytest.raises(FeatureValidationError):
        validate_vector([{"URLLength": 1}] + good[1:])  # the original dict-vs-vector bug
