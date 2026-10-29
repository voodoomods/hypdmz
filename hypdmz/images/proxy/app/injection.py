"""
Credential injection — applies vault entries to in-flight requests.

Called from the proxy's request handler after firewall verdict and DLP,
before forwarding upstream. Mutates `headers` in place (and returns the
list of credential names actually injected for audit purposes).

Threat model:
  - The credential plaintext is materialised here for the duration of
    one .format() call. Do not log the result.
  - If the rule names a credential that doesn't exist in the vault, the
    injection is silently skipped — never proxy with a half-applied
    auth header.
  - scope_host / scope_path on the credential record are an additional
    guardrail beyond what the firewall rule already enforced.
"""

import re
from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl

from . import vault


def _scope_match(scope: str | None, value: str) -> bool:
    if not scope:
        return True
    # Glob-ish: leading '.' = label-anchored suffix; '*' = wildcard.
    if scope.startswith("."):
        return value == scope[1:] or value.endswith(scope)
    if "*" in scope:
        pat = "^" + re.escape(scope).replace(r"\*", ".*") + "$"
        return re.match(pat, value) is not None
    return value == scope


def apply(
    *,
    cred_names: list[str] | None,
    host: str,
    path: str,
    headers: dict[str, str],
    url: str,
) -> tuple[dict[str, str], str, list[str]]:
    """Apply each named credential to the in-flight request.

    Returns (mutated_headers, mutated_url, applied_names).
    `headers` is a fresh dict; the caller should swap it for `mutated_headers`.
    """
    if not cred_names:
        return headers, url, []

    new_headers = dict(headers)
    new_url = url
    applied: list[str] = []

    for name in cred_names:
        rec = vault.get_for_inject(name)
        if not rec:
            continue
        if not _scope_match(rec.get("scope_host"), host):
            continue
        if not _scope_match(rec.get("scope_path"), path):
            continue

        try:
            rendered = rec["inject_template"].format(value=rec["value"])
        except Exception:
            continue

        loc = rec["inject_location"]
        iname = rec["inject_name"]
        overwrite = rec["inject_overwrite"]

        if loc == "header":
            # Defense in depth: strip any incoming header of the same name first.
            for k in list(new_headers.keys()):
                if k.lower() == iname.lower():
                    if overwrite:
                        del new_headers[k]
                    else:
                        rendered = None
                        break
            if rendered is not None:
                new_headers[iname] = rendered
                applied.append(name)
        elif loc == "query":
            parsed = urlparse(new_url)
            qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
            if iname in qs and not overwrite:
                continue
            qs[iname] = rendered
            new_url = urlunparse(parsed._replace(query=urlencode(qs)))
            applied.append(name)
        elif loc == "body":
            # Body injection is non-trivial (JSON vs form) and rarely safe.
            # Phase 5 may add this; for now skip with a warning.
            print(f"[injection] body location not yet supported for {name}")

    return new_headers, new_url, applied
