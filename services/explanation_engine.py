"""Human-readable explanations generated only from values that were actually computed.

Two kinds of item are produced, and the UI shows which is which:

  "model_feature"  A model input feature whose value is unusual compared with
                   legitimate URLs in the training data (percentiles stored in
                   models/model_metadata.json -> legitimate_reference). This is
                   evidence about the input, not a per-prediction attribution: the
                   model may weigh the feature differently.
  "observation"    A structural fact about the submitted URL that the model does
                   NOT use (e.g. a non-standard port). Reported for the user's
                   benefit and never presented as the reason for the model's score.

Each item: {"source", "severity" ("risk" | "caution" | "info"), "feature" | "check", "message"}.
"""

from ml.url_utils import registrable_domain

# Model features where a high value (relative to legitimate URLs) is noteworthy. "Assessed domain" is the
# model input (the registrable domain in the default view, the full host in the "host" view), with "www.".
_HIGH_VALUE_MESSAGES = {
    "DomainLength": "The assessed domain is {value} characters long; 95% of legitimate training domains are at most "
                    "{p95:g}.",
    "NoOfSubDomain": "The assessed domain has {value} dot-separated level(s) after 'www'; 95% of legitimate training "
                     "domains have at most {p95:g}.",
    "NoOfDegitsInURL": "The assessed domain contains {value} digit(s); 95% of legitimate training domains contain at "
                       "most {p95:g}.",
    "NoOfOtherSpecialCharsInURL": "The assessed domain contains {value} separator/special character(s) such as '-' "
                                  "or '.'; 95% of legitimate training domains contain at most {p95:g}.",
    "TLDLength": "Top-level domain is {value} characters long; 95% of legitimate training URLs use at most {p95:g}.",
}


def _fmt(value):
    return f"{value:g}" if isinstance(value, float) else str(value)


# Domain-name features that are meaningless when the host is an IP address.
_DOMAIN_ONLY = {"TLDLength", "NoOfSubDomain", "TLDLegitimateProb", "CharContinuationRate"}


def _subdomain_items(url_facts, view):
    """Observations about the part of the host below the registrable domain (never used by the model)."""
    sub, registrable = url_facts.get("subdomain") or "", url_facts.get("registrable_domain") or ""
    if not registrable or sub in ("", "www"):
        return []
    items = []
    if view == "registrable":
        items.append({"source": "observation", "severity": "info", "check": "subdomain",
                      "message": f"The model assessed the registrable domain {registrable}; the subdomain '{sub}' is "
                                 "not part of the model input."})
    embedded = registrable_domain(sub) if "." in sub else ""
    if embedded:
        items.append({"source": "observation", "severity": "caution", "check": "embedded_domain",
                      "message": f"The subdomain contains another domain name ({embedded}) in front of the real "
                                 f"registrable domain {registrable}, a common way to imitate a trusted site. The "
                                 "model does not score this pattern."})
    elif sub.count(".") >= 2:
        items.append({"source": "observation", "severity": "caution", "check": "deep_subdomain",
                      "message": f"The host has {sub.count('.') + 1} subdomain levels below {registrable}."})
    return items


def explain(features, url_facts, reference, scheme_assumed=False, view="host"):
    items = []
    host_is_ip = features.get("IsDomainIP") == 1

    if host_is_ip:
        items.append({"source": "model_feature", "severity": "risk", "feature": "IsDomainIP",
                      "message": "Host is (or contains) an IP address instead of a domain name."})

    tld_prob = features.get("TLDLegitimateProb")
    if not host_is_ip and tld_prob is not None and tld_prob == 0.0:
        items.append({"source": "model_feature", "severity": "caution", "feature": "TLDLegitimateProb",
                      "message": "Top-level domain has no legitimacy prior in the dataset's TLD table "
                                 "(unseen or never associated with legitimate sites)."})

    for name, template in _HIGH_VALUE_MESSAGES.items():
        if host_is_ip and name in _DOMAIN_ONLY:
            continue
        value, ref = features.get(name), reference.get(name)
        if value is None or not ref:
            continue
        if value > ref["p99"]:
            severity = "risk"
        elif value > ref["p95"]:
            severity = "caution"
        else:
            continue
        items.append({"source": "model_feature", "severity": severity, "feature": name,
                      "message": template.format(value=_fmt(value), p95=ref["p95"])})

    ccr, ccr_ref = features.get("CharContinuationRate"), reference.get("CharContinuationRate")
    if not host_is_ip and ccr is not None and ccr_ref and ccr < ccr_ref["p5"]:
        items.append({"source": "model_feature", "severity": "caution", "feature": "CharContinuationRate",
                      "message": f"Host name mixes letters, digits and symbols irregularly (continuation "
                                 f"rate {ccr:.2f}; 95% of legitimate training hosts are at least {ccr_ref['p5']:.2f})."})

    # Structural observations (not model inputs).
    if url_facts.get("has_userinfo"):
        items.append({"source": "observation", "severity": "risk", "check": "userinfo",
                      "message": "URL contains '@' before the host; text before '@' is ignored by browsers "
                                 "and is a common way to disguise the real destination."})
    if url_facts.get("is_punycode"):
        items.append({"source": "observation", "severity": "caution", "check": "punycode",
                      "message": "Host uses an internationalised (punycode 'xn--') name, which can imitate "
                                 "other domains with look-alike characters."})
    if url_facts.get("non_standard_port"):
        items.append({"source": "observation", "severity": "caution", "check": "port",
                      "message": f"URL uses non-standard port {url_facts.get('port')}."})
    if url_facts.get("scheme") == "http":
        items.append({"source": "observation", "severity": "caution", "check": "https",
                      "message": "Connection does not use HTTPS."})
    if url_facts.get("is_private_or_local"):
        items.append({"source": "observation", "severity": "info", "check": "local",
                      "message": "Host is a local or private-network address; the model was trained on "
                                 "public web URLs, so its score is not meaningful here."})
    if url_facts.get("hyphen_in_host"):
        items.append({"source": "observation", "severity": "info", "check": "hyphen",
                      "message": "Host name contains '-', which phishing domains often use to add "
                                 "brand names or keywords."})
    items.extend(_subdomain_items(url_facts, view))
    if scheme_assumed:
        items.append({"source": "observation", "severity": "info", "check": "scheme",
                      "message": "No scheme was given, so https:// was assumed."})

    if not any(item["severity"] in ("risk", "caution") for item in items):
        items.append({"source": "model_feature", "severity": "info", "feature": None,
                      "message": "No host feature is outside the range typical of legitimate training URLs."})
    return items
