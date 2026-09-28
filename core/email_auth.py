"""Email Authentication Analysis: SPF, DMARC, DKIM, and BIMI.

Provides deep cryptographic and DNS-based posture assessment for email security:
- SPF (Sender Policy Framework - RFC 7208): Syntax validation, mechanism parsing,
  DNS lookup count limit enforcement (RFC 7208 10-lookup limit), and policy evaluation.
- DMARC (Domain-based Message Authentication - RFC 7489): Policy enforcement (reject,
  quarantine, none), reporting configurations (rua/ruf), percentage alignment, and spoofability.
- DKIM (DomainKeys Identified Mail - RFC 6376): Common selector probing, public key strength
  audit (RSA 1024 vs 2048+ bit), and syntax validation.
- BIMI (Brand Indicators for Message Identification): VMC / SVG record check.
"""

from __future__ import annotations

import base64
import re
from typing import Any, Dict, List, Optional

try:
    import dns.resolver
    import dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


def _get_resolver() -> Any:
    """Create a configured DNS resolver with fast, reliable public resolvers and reasonable timeouts."""
    if not HAS_DNS:
        return None
    res = dns.resolver.Resolver(configure=True)
    # Ensure fast fallback servers to avoid Windows inactive adapter delays
    res.nameservers = ["1.1.1.1", "8.8.8.8"] + [ns for ns in res.nameservers if ns not in ("1.1.1.1", "8.8.8.8")]
    res.timeout = 2.0
    res.lifetime = 3.0
    return res


def query_txt_records(name: str) -> List[str]:
    """Fetch TXT records for a given DNS name."""
    if not HAS_DNS:
        return []
    res = _get_resolver()
    if not res:
        return []
    try:
        answers = res.resolve(name, "TXT")
        records = []
        for rdata in answers:
            # Combine chunked TXT strings into a single string
            text = "".join(
                s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s)
                for s in rdata.strings
            )
            records.append(text)
        return records
    except Exception:
        return []


def check_spf(domain: str) -> Dict[str, Any]:
    """Analyze SPF configuration for a domain."""
    txt_records = query_txt_records(domain)
    spf_records = [r for r in txt_records if r.startswith("v=spf1")]

    result: Dict[str, Any] = {
        "domain": domain,
        "present": False,
        "record": None,
        "multiple_records": False,
        "policy": "none",
        "qualifier": None,
        "lookup_count": 0,
        "exceeds_lookup_limit": False,
        "mechanisms": [],
        "includes": [],
        "score": 0.0,
        "status": "FAIL",
        "findings": [],
        "recommendations": [],
    }

    if not spf_records:
        result["findings"].append({
            "id": "spf.missing",
            "title": "SPF Record Missing",
            "severity": "critical",
            "description": f"Domain {domain} has no SPF record. Mail spoofing is unrestricted.",
        })
        result["recommendations"].append(f"Publish a valid SPF record: 'v=spf1 mx ~all' or 'v=spf1 -all' at {domain}")
        return result

    if len(spf_records) > 1:
        result["multiple_records"] = True
        result["findings"].append({
            "id": "spf.multiple",
            "title": "Multiple SPF Records Detected",
            "severity": "high",
            "description": "RFC 7208 states a domain must not publish multiple SPF records. Mail receivers may treat this as PermError and fail all SPF checks.",
        })
        result["recommendations"].append("Merge all SPF directives into a single valid TXT record.")

    spf = spf_records[0]
    result["present"] = True
    result["record"] = spf

    tokens = spf.split()
    lookups = 0
    includes = []
    qualifier = None

    redirect_domain = None
    for term in tokens[1:]:
        t = term.lower()
        if t.startswith("include:"):
            lookups += 1
            inc_domain = t.split(":", 1)[1]
            includes.append(inc_domain)
            result["mechanisms"].append(t)
        elif t.startswith("redirect="):
            lookups += 1
            redirect_domain = t.split("=", 1)[1]
            result["mechanisms"].append(t)
        elif t in ("a", "+a", "mx", "+mx", "ptr", "+ptr", "exists", "+exists") or t.startswith(("a:", "+a:", "mx:", "+mx:", "ptr:", "+ptr:")):
            lookups += 1
            result["mechanisms"].append(t)
        elif t.endswith("all"):
            qualifier = t
            result["mechanisms"].append(t)
        else:
            result["mechanisms"].append(t)

    # If redirect= is present and no local 'all', follow redirect target to check its qualifier
    if redirect_domain and not qualifier:
        red_txt = query_txt_records(redirect_domain)
        red_spf = [r for r in red_txt if r.startswith("v=spf1")]
        if red_spf:
            red_tokens = red_spf[0].split()
            for r_term in red_tokens[1:]:
                if r_term.lower().endswith("all"):
                    qualifier = r_term.lower()
                    break

    result["lookup_count"] = lookups
    result["includes"] = includes
    result["qualifier"] = qualifier
    result["redirect"] = redirect_domain

    if lookups > 10:
        result["exceeds_lookup_limit"] = True
        result["findings"].append({
            "id": "spf.lookup_limit_exceeded",
            "title": "SPF 10-DNS-Lookup Limit Exceeded",
            "severity": "high",
            "description": f"SPF record requires {lookups} DNS lookups, exceeding the RFC 7208 limit of 10. Receivers will return PermError.",
        })
        result["recommendations"].append("Flatten SPF record by inlining IP addresses or removing unnecessary includes.")

    # Score calculation
    base_score = 70.0
    if qualifier == "-all":
        result["policy"] = "hardfail"
        base_score = 100.0
    elif qualifier == "~all":
        result["policy"] = "softfail"
        base_score = 85.0
    elif redirect_domain and not qualifier:
        result["policy"] = f"redirect({redirect_domain})"
        base_score = 80.0
    elif qualifier in ("?all", "+all"):
        result["policy"] = "permissive"
        base_score = 30.0
        result["findings"].append({
            "id": "spf.permissive_all",
            "title": f"SPF Uses Insecure '{qualifier}' Policy",
            "severity": "high",
            "description": f"The '{qualifier}' mechanism permits untrusted servers or neutralizes SPF protection.",
        })
        result["recommendations"].append("Change qualifier to '~all' or '-all' to enforce sender authorization.")
    elif not qualifier:
        result["policy"] = "missing_all"
        base_score = 40.0
        result["findings"].append({
            "id": "spf.missing_all_mechanism",
            "title": "SPF Missing Terminal 'all' Qualifier",
            "severity": "medium",
            "description": "SPF record does not specify a terminal 'all' directive, leading to undefined evaluation behavior.",
        })
        result["recommendations"].append("Append '-all' or '~all' at the end of your SPF record.")

    if result["multiple_records"]:
        base_score -= 30.0
    if result["exceeds_lookup_limit"]:
        base_score -= 25.0

    result["score"] = max(0.0, min(100.0, base_score))
    result["status"] = "PASS" if result["score"] >= 75 else ("WARN" if result["score"] >= 50 else "FAIL")
    return result


def check_dmarc(domain: str) -> Dict[str, Any]:
    """Analyze DMARC configuration for a domain."""
    dmarc_name = f"_dmarc.{domain}"
    txt_records = query_txt_records(dmarc_name)
    dmarc_records = [r for r in txt_records if r.startswith("v=DMARC1")]

    # If not found on subdomain, check parent domain if applicable
    if not dmarc_records and domain.count(".") > 1:
        parts = domain.split(".")
        parent_domain = ".".join(parts[1:])
        parent_txt = query_txt_records(f"_dmarc.{parent_domain}")
        dmarc_records = [r for r in parent_txt if r.startswith("v=DMARC1")]

    result: Dict[str, Any] = {
        "domain": domain,
        "present": False,
        "record": None,
        "policy": "none",
        "subdomain_policy": None,
        "pct": 100,
        "rua": [],
        "ruf": [],
        "adkim": "r",
        "aspf": "r",
        "spoofing_protected": False,
        "score": 0.0,
        "status": "FAIL",
        "findings": [],
        "recommendations": [],
    }

    if not dmarc_records:
        result["findings"].append({
            "id": "dmarc.missing",
            "title": "DMARC Record Missing",
            "severity": "critical",
            "description": f"Domain {domain} lacks a DMARC policy. Attackers can forge emails appearing to originate from your domain without detection.",
        })
        result["recommendations"].append(f"Publish a DMARC record at _dmarc.{domain}: 'v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@{domain}'")
        return result

    dmarc = dmarc_records[0]
    result["present"] = True
    result["record"] = dmarc

    # Parse tags (key=value)
    tags: Dict[str, str] = {}
    for part in dmarc.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()

    policy = tags.get("p", "none").lower()
    sub_policy = tags.get("sp", policy).lower()
    pct = 100
    if "pct" in tags:
        try:
            pct = int(tags["pct"])
        except ValueError:
            pct = 100

    rua = [u.strip() for u in tags.get("rua", "").split(",") if u.strip()]
    ruf = [u.strip() for u in tags.get("ruf", "").split(",") if u.strip()]

    result["policy"] = policy
    result["subdomain_policy"] = sub_policy
    result["pct"] = pct
    result["rua"] = rua
    result["ruf"] = ruf
    result["adkim"] = tags.get("adkim", "r").lower()
    result["aspf"] = tags.get("aspf", "r").lower()

    # Evaluation
    score = 0.0
    if policy == "reject":
        score = 100.0
        result["spoofing_protected"] = True
    elif policy == "quarantine":
        score = 80.0
        result["spoofing_protected"] = True
    elif policy == "none":
        score = 40.0
        result["spoofing_protected"] = False
        result["findings"].append({
            "id": "dmarc.policy_none",
            "title": "DMARC Policy Set to 'none' (Monitoring Only)",
            "severity": "high",
            "description": "Policy p=none does not instruct receivers to reject or quarantine fraudulent messages. Domain spoofing remains unblocked.",
        })
        result["recommendations"].append("Graduate DMARC policy from 'p=none' to 'p=quarantine' or 'p=reject' once legitimate senders are verified.")

    if pct < 100:
        score -= (100 - pct) * 0.3
        result["findings"].append({
            "id": "dmarc.partial_enforcement",
            "title": f"DMARC Partial Enforcement (pct={pct}%)",
            "severity": "medium",
            "description": f"DMARC is only applied to {pct}% of incoming mail. {100 - pct}% bypasses policy enforcement.",
        })
        result["recommendations"].append("Set pct=100 for full organizational protection.")

    if not rua:
        score -= 15.0
        result["findings"].append({
            "id": "dmarc.rua_missing",
            "title": "DMARC Aggregate Reporting (rua) Not Configured",
            "severity": "medium",
            "description": "Without 'rua' aggregate reports, administrators have no visibility into spoofing campaigns or delivery failures.",
        })
        result["recommendations"].append(f"Add aggregate reporting URI: 'rua=mailto:dmarc-reports@{domain}'")

    result["score"] = max(0.0, min(100.0, score))
    result["status"] = "PASS" if result["score"] >= 80 else ("WARN" if result["score"] >= 50 else "FAIL")
    return result


def check_dkim(domain: str, custom_selectors: Optional[List[str]] = None) -> Dict[str, Any]:
    """Probe common DKIM selectors for a domain."""
    from concurrent.futures import ThreadPoolExecutor

    selectors = custom_selectors or [
        "google", "default", "selector1", "k1", "k2", "mail", "smtp",
        "s1", "s2", "dkim", "2023", "2024", "2025", "2026"
    ]

    discovered = []

    def _probe_selector(sel: str) -> List[Dict[str, Any]]:
        qname = f"{sel}._domainkey.{domain}"
        found = []
        records = query_txt_records(qname)
        for r in records:
            if "v=dkim1" in r.lower() or "p=" in r.lower():
                # Extract public key
                m = re.search(r'p=([a-zA-Z0-9+/=]+)', r)
                key_b64 = m.group(1) if m else ""
                key_bits = None
                if key_b64:
                    try:
                        raw = base64.b64decode(key_b64)
                        key_bits = len(raw) * 8
                    except Exception:
                        pass

                found.append({
                    "selector": sel,
                    "record_name": qname,
                    "record_text": r[:120] + "..." if len(r) > 120 else r,
                    "key_length_bits": key_bits,
                    "is_weak": (key_bits is not None and key_bits < 2048),
                })
        return found

    with ThreadPoolExecutor(max_workers=min(len(selectors), 10)) as executor:
        for res_list in executor.map(_probe_selector, selectors):
            discovered.extend(res_list)

    result: Dict[str, Any] = {
        "domain": domain,
        "selectors_probed": len(selectors),
        "selectors_found": len(discovered),
        "keys": discovered,
        "score": 85.0 if discovered else 50.0,
        "status": "PASS" if discovered else "INFO",
        "findings": [],
        "recommendations": [],
    }

    weak_keys = [k for k in discovered if k["is_weak"]]
    if weak_keys:
        result["score"] -= 20.0
        result["findings"].append({
            "id": "dkim.weak_key",
            "title": "Weak DKIM Key Length (< 2048 bits)",
            "severity": "high",
            "description": f"Found DKIM selector '{weak_keys[0]['selector']}' utilizing a key length under 2048 bits. Susceptible to factorization.",
        })
        result["recommendations"].append("Rotate to 2048-bit or 4096-bit RSA keys for all DKIM selectors.")

    if not discovered:
        result["findings"].append({
            "id": "dkim.no_standard_selectors",
            "title": "No Standard DKIM Selectors Discovered",
            "severity": "info",
            "description": f"No public DKIM keys found under standard selectors ({', '.join(selectors[:5])}...). Domain may use proprietary or mail-provider specific selectors.",
        })
        result["recommendations"].append("Verify active DKIM selectors via outgoing mail headers (DKIM-Signature 's=' tag).")

    return result


def check_bimi(domain: str) -> Dict[str, Any]:
    """Check BIMI (Brand Indicators for Message Identification) record."""
    bimi_name = f"default._bimi.{domain}"
    records = query_txt_records(bimi_name)
    bimi_records = [r for r in records if "v=bimi1" in r.lower()]

    result = {
        "present": bool(bimi_records),
        "record": bimi_records[0] if bimi_records else None,
        "logo_url": None,
        "vmc_cert": None,
    }
    if bimi_records:
        r = bimi_records[0]
        m_logo = re.search(r'l=([^\s;]+)', r)
        if m_logo:
            result["logo_url"] = m_logo.group(1)
        m_cert = re.search(r'a=([^\s;]+)', r)
        if m_cert:
            result["vmc_cert"] = m_cert.group(1)
    return result


def evaluate_email_auth(domain: str) -> Dict[str, Any]:
    """Compute consolidated email authentication assessment for a domain."""
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=4) as executor:
        f_spf = executor.submit(check_spf, domain)
        f_dmarc = executor.submit(check_dmarc, domain)
        f_dkim = executor.submit(check_dkim, domain)
        f_bimi = executor.submit(check_bimi, domain)

        spf_res = f_spf.result()
        dmarc_res = f_dmarc.result()
        dkim_res = f_dkim.result()
        bimi_res = f_bimi.result()

    # Weighted calculation: DMARC (45%), SPF (35%), DKIM (20%)
    overall_score = round(
        (dmarc_res["score"] * 0.45) +
        (spf_res["score"] * 0.35) +
        (dkim_res["score"] * 0.20),
        1
    )

    if overall_score >= 90:
        grade = "A+"
        grade_color = "#38a856"
        summary = "Exceptional email authentication. Domain is robustly protected against spoofing and phishing."
    elif overall_score >= 80:
        grade = "A"
        grade_color = "#38a856"
        summary = "Strong email authentication posture. Minor adjustments recommended to achieve strict enforcement."
    elif overall_score >= 70:
        grade = "B"
        grade_color = "#1982c4"
        summary = "Moderate email protection. Policies present but allow potential bypass or lack strict reject enforcement."
    elif overall_score >= 50:
        grade = "C"
        grade_color = "#ffca3a"
        summary = "Weak email authentication. Domain is susceptible to targeted spoofing and delivery tampering."
    else:
        grade = "F"
        grade_color = "#ff595e"
        summary = "Critical email security failure. Domain lacks fundamental anti-spoofing protections."

    # Consolidate findings
    all_findings = spf_res["findings"] + dmarc_res["findings"] + dkim_res["findings"]
    all_recommendations = spf_res["recommendations"] + dmarc_res["recommendations"] + dkim_res["recommendations"]

    return {
        "domain": domain,
        "overall_score": overall_score,
        "grade": grade,
        "grade_color": grade_color,
        "summary": summary,
        "spf": spf_res,
        "dmarc": dmarc_res,
        "dkim": dkim_res,
        "bimi": bimi_res,
        "findings": all_findings,
        "recommendations": list(dict.fromkeys(all_recommendations)),  # deduplicate preserving order
    }
