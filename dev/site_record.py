"""
hypdmz.com's own HypGraph record: every figure on the page, bound to the measurement it came from, re-measured
another way, and the page's text linted against it — the site held to the rules the swarm runs under.

    python dev/site_record.py            # from site/data/evidence/*  →  site/data/site-record.bundle.json,
                                         #                                site/data/page-checked.md, site/assets/site-data.js
    python dev/site_record.py --live     # the reviewer also re-runs `hypdmz egress-check` against the running pod

The evidence is what the pod printed, captured as files (see docs/DESIGN.md → "The record behind the page"):
egress-check.json, status.json, audit-verify.json, proxy_events.jsonl (the audit chain itself), the swarm container's
HostConfig and environment, the proxy's environment, and the exported bundles of the swarms that ran inside the pod.

Three authors, as the record's roles intend:
- ``lab`` (the instrument — here, the pod) measures: probes passed, calls that carried the vaulted key, calls the cap
  refused, the chain's length, the swarms' outcomes, the container's limits;
- ``site`` writes the page's claims, each bound to the lab's result for its numbers;
- ``site-check`` (the reviewer) re-measures each another way — the probe table re-judged from the raw observations,
  the audit file re-read with a regex instead of a JSON parser, the hash chain re-walked with its own sha256, the
  swarms' standing read from their records instead of their telemetry, the container's limits read from podman's
  config against what the probes saw from inside — and records what it found.

Then the page's text goes through `hypgraph check` against this record. A phrase true by design is marked
`data-ok="<why>"` and listed on the page.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from hypgraph import Graph, Policy, report_check
from hypgraph import derive as D
from hypgraph.bundle import verify_bundle

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"
PAGE = SITE / "index.html"
EV = SITE / "data" / "evidence"

# which probes are refusals that answer with an HTTP error (a 2xx/3xx would be the breach), as egress.py defines them
HTTP_ERROR_IS_BLOCKED = {"proxy-denies-unlisted", "proxy-relay-to-console"}
LIMIT_PROBES = {"swarm-rootfs-readonly", "swarm-memory-capped", "swarm-pids-capped", "swarm-cpu-capped"}


def now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def J(name: str) -> dict:
    return json.loads((EV / name).read_text(encoding="utf-8"))


# ── the lab's measurements (what the pod printed) ──────────────────────────────────────────────────────────────
def probes() -> dict:
    d = J("egress-check.json")
    rs = d["results"]
    cat = {"blocked": [], "limits": [], "controls": [], "console": []}
    for r in rs:
        if r["name"].startswith("console-"):
            cat["console"].append(r)
        elif r["name"] in LIMIT_PROBES:
            cat["limits"].append(r)
        elif r["kind"] == "blocked":
            cat["blocked"].append(r)
        else:
            cat["controls"].append(r)
    kn = lambda rows: {"k": sum(1 for r in rows if r["passed"]), "n": len(rows)}
    return {"all": kn(rs), **{k: kn(v) for k, v in cat.items()}, "lockdown": d["lockdown_state"], "ok": d["ok"],
            "caps": d.get("caps") or {}, "results": rs}


def audit_lines() -> list[dict]:
    return [json.loads(ln) for ln in (EV / "proxy_events.jsonl").read_text(encoding="utf-8").splitlines() if ln.strip()]


def key_calls(rows: list[dict]) -> dict:
    """Model calls (POST …/chat/completions, forwarded) and how many carried the vaulted credential."""
    calls = [r for r in rows if r["decision"] == "allow" and r["method"] == "POST" and r["path"].endswith("/chat/completions")]
    inj = [r for r in calls if "model_api_key" in (r.get("injected") or [])]
    swarm_env = J("swarm-env.json")
    proxy_env = J("proxy-env.json")
    # calls without the credential: made before any key was vaulted, and refused upstream
    bare_401 = [r for r in calls if not r.get("injected") and r.get("status_code") == 401]
    return {"calls": {"k": len(inj), "n": len(calls)}, "without_key_401": len(bare_401),
            "placeholder_in_swarm_env": sum(1 for e in swarm_env if e == "OPENAI_API_KEY=__hypdmz_inject__"),
            "key_values_in_proxy_env": sum(1 for e in proxy_env if e.startswith("VAULT_BOOTSTRAP_MODEL=")),
            "key_file_in_proxy_env": sum(1 for e in proxy_env if e.startswith("VAULT_BOOTSTRAP_MODEL_FILE=/run/secrets/"))}


def cap_refusals(rows: list[dict]) -> dict:
    hits = [r for r in rows if str(r.get("matched_rule", "")).startswith("limit:")]
    return {"refused": len(hits), "status_429": sum(1 for r in hits if r.get("status_code") == 429)}


def chain() -> dict:
    v = J("audit-verify.json")
    return {"ok": bool(v.get("ok")), "events": int(v.get("events") or 0), "head": v.get("head", "")}


SWARM_BUNDLE = "swarm.bundle.json"     # the pod's whole record (/records/swarm.hypgraph) with its telemetry


def swarms() -> dict:
    """One run per investigation in the pod's record, as the telemetry sidecar tells it (run_end: stopped, calls, usd)."""
    b = J(SWARM_BUNDLE)
    assert verify_bundle(b)["ok"], SWARM_BUNDLE
    tel = (b.get("telemetry") or {}).get("events", [])
    out = []
    for end in [t for t in tel if t["kind"] == "run_end"]:
        inv = end.get("inv", "")
        out.append({"inv": inv, "settled": end.get("stopped") == "settled", "calls": int(end.get("calls") or 0),
                    "usd": float(end.get("usd") or 0), "seconds": float(end.get("seconds") or 0),
                    "model_calls_telemetry": sum(1 for t in tel if t["kind"] == "model_end" and t.get("inv") == inv)})
    return {"runs": out, "settled": {"k": sum(r["settled"] for r in out), "n": len(out)},
            "calls": sum(r["calls"] for r in out), "usd": round(sum(r["usd"] for r in out), 4)}


def edges() -> dict:
    h = J("swarm-hostconfig.json")
    return {"readonly": 1 if h.get("ReadonlyRootfs") else 0, "memory_gib": round((h.get("Memory") or 0) / 2**30, 2),
            "pids": int(h.get("PidsLimit") or 0), "cpus": round((h.get("NanoCpus") or 0) / 1e9, 2),
            "cap_add": sorted(h.get("CapAdd") or []), "cap_drop": sorted(h.get("CapDrop") or [])}


# ── the reviewer's re-measurements (another way) ───────────────────────────────────────────────────────────────
def rejudge_probes(results: list[dict]) -> int:
    """Count passes from the raw observations with the probe rules, instead of trusting the `passed` flags."""
    def ok(r):
        o = r["observed"]
        got_through = o == "ok" or (o.isdigit() and o != "000")
        if r["kind"] == "control":
            return got_through if r["name"] != "console-with-token" else o == "200"
        if r["name"] == "console-requires-token":
            return o == "401"
        if r["name"] in HTTP_ERROR_IS_BLOCKED:
            return not (o.isdigit() and 200 <= int(o) < 400)
        return not got_through
    return sum(1 for r in results if ok(r))


def live_egress_check() -> dict | None:
    """With --live: run `hypdmz egress-check --json` again against the pod (the launcher must be importable)."""
    for root in (ROOT, ROOT.parent / "hypdmz-scaffold"):
        if (root / "hypdmz" / "cli.py").exists():
            p = subprocess.run([sys.executable, "-m", "hypdmz", "--repo-root", str(root), "egress-check", "--json"],
                               cwd=root, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)
            try:
                return json.loads(p.stdout)
            except json.JSONDecodeError:
                return None
    return None


def regex_counts() -> dict:
    txt = (EV / "proxy_events.jsonl").read_text(encoding="utf-8")
    chat = [ln for ln in txt.splitlines() if '"decision": "allow"' in ln and '"method": "POST"' in ln and "/chat/completions" in ln]
    return {"calls": len(chat), "injected": sum(1 for ln in chat if '"injected": ["model_api_key"]' in ln),
            "limit": len(re.findall(r'"matched_rule": "limit:', txt))}


def rewalk_chain() -> dict:
    """Re-verify the audit file with an independent sha256 walk (the proxy's `verify()` did it once already)."""
    prev, n = "GENESIS", 0
    for ln in (EV / "proxy_events.jsonl").read_text(encoding="utf-8").splitlines():
        if not ln.strip():
            continue
        ev = json.loads(ln)
        if ev.get("prev_hash") != prev:
            return {"ok": False, "events": n, "why": "prev_hash"}
        body = {k: v for k, v in ev.items() if k not in ("hash", "id")}
        h = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        if h != ev.get("hash"):
            return {"ok": False, "events": n, "why": "hash"}
        prev, n = h, n + 1
    return {"ok": True, "events": n, "head": prev}


def swarms_from_records() -> dict:
    """Each swarm's standing from the record itself (completion, claims checked) instead of from its telemetry."""
    g = Graph.from_bundle(J(SWARM_BUNDLE))
    out = []
    try:
        s = g.snapshot()
        for i in g.investigations():
            inv = i["id"]
            comp = g.completion(inv)
            claims = [nid for nid, nd in s.nodes.items() if nd.get("type") == "claim" and nd.get("inv") == inv]
            checked = sum(1 for c in claims if (D.state(s, c).get("review") or {}).get("state") in ("checked", "replicated"))
            out.append({"inv": inv, "complete": bool(comp.get("complete")), "claims": len(claims), "checked": checked,
                        "refused": g.refusal_report(inv).get("refused", 0)})
    finally:
        g.close()
    return {"runs": out, "complete": sum(r["complete"] for r in out)}


# ── the record ─────────────────────────────────────────────────────────────────────────────────────────────────
def build(live: bool) -> tuple[Graph, str, dict]:
    g = Graph(Path(tempfile.mkdtemp()) / "site-record.hypgraph",
              policy=Policy(reviewers=frozenset({"site-check"}), max_creates_per_minute=10**6))
    site, lab, check = g.author("site"), g.author("lab"), g.author("site-check")
    inv = site.investigation("What hypdmz.com claims",
                             "Bind every figure on hypdmz.com to what the pod printed, and have each re-measured "
                             "another way before the page is published.")["id"]
    nodes: dict[str, dict] = {}
    t0 = now()

    def measure(key, question, run_name, code, summary, values, exit_code=0):
        q = site.add("question", inv, text=question)["id"]
        r = lab.add("run", inv, kind="lab", state="succeeded" if exit_code == 0 else "failed", name=run_name,
                    code=[code], started=t0, finished=now(), exit_code=exit_code)["id"]
        rs = lab.add("result", inv, kind="computed", outcome="positive" if exit_code == 0 else "failed", summary=summary,
                     values=values, links=[{"rel": "produced", "from": r}])["id"]
        nodes[key] = {"question": q, "result": rs}

    def claim(key, statement, scope, measurements):
        rs = nodes[key]["result"]
        cl = site.add("claim", inv, statement=statement, scope=scope,
                      measurements=[{**m, "result": rs} for m in measurements],
                      links=[{"rel": "answers", "to": nodes[key]["question"]}, {"rel": "derived_from", "to": rs},
                             {"rel": "supports", "from": rs, "why": "the pod's own output of exactly this"}])
        nodes[key].update(claim=cl["id"], code=cl.get("code"))

    P = probes()
    measure("probes", "Does the egress floor hold, from the swarm's own seat?", "hypdmz egress-check --json",
            "hypdmz egress-check --json  (19 probes as the swarm user inside the swarm container, 2 from the host)",
            f"{P['all']['k']} of {P['all']['n']} probes passed: {P['blocked']['k']} of {P['blocked']['n']} escape routes blocked, "
            f"{P['limits']['k']} of {P['limits']['n']} limits present, {P['controls']['k']} of {P['controls']['n']} controls reachable, "
            f"{P['console']['k']} of {P['console']['n']} console checks right. Lockdown: {P['lockdown'].split(' ')[0]}.",
            {"probes": P["all"], "blocked": P["blocked"], "limits": P["limits"], "controls": P["controls"], "console": P["console"]},
            0 if P["ok"] else 1)
    claim("probes", f"{P['all']['k']} of {P['all']['n']} egress-check probes passed: {P['blocked']['k']} of {P['blocked']['n']} "
          f"escape routes blocked, {P['limits']['k']} of {P['limits']['n']} limits present, {P['controls']['k']} of "
          f"{P['controls']['n']} controls reachable, and the console answered as it should in {P['console']['k']} of {P['console']['n']} checks.",
          "One pod on one Windows 11 host (Podman Desktop, WSL2), 2026-10-29; probes run as the swarm user inside the swarm container, the console checks from the host.",
          [{"name": "probes passed", "key": "probes", **P["all"]}, {"name": "escape routes blocked", "key": "blocked", **P["blocked"]},
           {"name": "limits present", "key": "limits", **P["limits"]}, {"name": "controls reachable", "key": "controls", **P["controls"]},
           {"name": "console checks", "key": "console", **P["console"]}])

    rows = audit_lines()
    K = key_calls(rows)
    measure("key", "Did the swarm ever hold the model API key?", "The audit chain and the containers' environments",
            "proxy_events.jsonl: POST …/chat/completions rows and their `injected`; podman inspect: the swarm's and the proxy's Config.Env",
            f"{K['calls']['k']} of {K['calls']['n']} forwarded model calls carried the vaulted credential ({K['without_key_401']} made before any key "
            f"was vaulted were refused upstream with 401); the swarm's environment holds the "
            f"placeholder ({K['placeholder_in_swarm_env']} entry); the proxy's environment holds {K['key_values_in_proxy_env']} key values and "
            f"{K['key_file_in_proxy_env']} path to the secret file.",
            {"calls": K["calls"], "without_key_401": K["without_key_401"], "status_401": 401,
             "placeholder_in_swarm_env": K["placeholder_in_swarm_env"],
             "key_values_in_proxy_env": K["key_values_in_proxy_env"], "key_file_in_proxy_env": K["key_file_in_proxy_env"]})
    claim("key", f"{K['calls']['k']} of {K['calls']['n']} model calls left the pod with the vaulted credential set by the proxy; the "
          f"{K['without_key_401']} without it were made before any key was vaulted and came back {401}. The swarm's environment holds a "
          f"placeholder, and the proxy's environment holds {K['key_values_in_proxy_env']} key values — only the path to the secret file.",
          "Every POST to /chat/completions in the pod's audit chain since it was created, 2026-10-29; environments as `podman inspect` reports them.",
          [{"name": "calls with the credential injected", "key": "calls", **K["calls"]},
           {"name": "calls before any key was vaulted", "key": "without_key_401", "value": K["without_key_401"]},
           {"name": "their upstream status", "key": "status_401", "value": 401},
           {"name": "key values in the proxy's environment", "key": "key_values_in_proxy_env", "value": K["key_values_in_proxy_env"]}])

    C = cap_refusals(rows)
    measure("cap", "Does the hourly cap refuse calls past it?", "The cap set to one call, then two calls from the swarm's seat",
            "firewall.json limits.calls_per_hour = 1; curl -x http://127.0.0.1:8080 $OPENAI_BASE_URL/models, twice, as the swarm user; audit rows with matched_rule limit:*",
            f"The cap refused {C['refused']} calls, {C['status_429']} of them with status 429, each audited as a denial.",
            {"refused": C["refused"], "status_429": C["status_429"], "status": 429})
    claim("cap", f"With the hourly cap set to one call, the proxy refused {C['refused']} calls with status {429} and audited each as a denial.",
          "A live test on 2026-10-29 with the cap at 1 call/hour, then restored to 1200.",
          [{"name": "calls refused by the cap", "key": "refused", "value": C["refused"]},
           {"name": "with that status", "key": "status_429", "value": C["status_429"]},
           {"name": "HTTP status", "key": "status", "value": 429}])

    H = chain()
    measure("chain", "Is the audit chain intact?", "GET /api/audit/verify", "the proxy re-walks proxy_events.jsonl: each line's hash over its content and the previous hash",
            f"Chain {'intact' if H['ok'] else 'BROKEN'} over {H['events']} events; head {H['head'][:16]}…", {"events": H["events"], "intact": 1 if H["ok"] else 0})
    claim("chain", f"The audit chain is intact over {H['events']} events.", "proxy_events.jsonl as exported on 2026-10-29.",
          [{"name": "events in the chain", "key": "events", "value": H["events"]}])

    S = swarms()
    measure("swarms", "Do swarms complete inside the pod?", "Two runs of examples/first-swarm --python",
            "hypdmz run examples/first-swarm --python; the records' telemetry run_end (stopped, calls, usd)",
            f"{S['settled']['k']} of {S['settled']['n']} swarm runs settled; {S['calls']} model calls, ${S['usd']:.4f} in total.",
            {"settled": S["settled"], "calls": S["calls"], "usd": S["usd"],
             **{f"run{i + 1}_{k}": v for i, r in enumerate(S["runs"])
                for k, v in (("seconds", round(r["seconds"])), ("calls", r["calls"]), ("usd", round(r["usd"], 2)))}})
    claim("swarms", f"{S['settled']['k']} of {S['settled']['n']} swarms run inside the pod settled, for {S['calls']} model calls in total.",
          "examples/first-swarm on DeepSeek-V4.1-Flash via DeepInfra, 2026-10-29; the records and their telemetry are on this page.",
          [{"name": "swarms settled", "key": "settled", **S["settled"]}, {"name": "model calls", "key": "calls", "value": S["calls"]}])

    E = edges()
    measure("edges", "What can the swarm's process consume?", "podman inspect hypdmz-swarm → HostConfig",
            "ReadonlyRootfs, Memory, PidsLimit, NanoCpus, CapAdd/CapDrop", f"Read-only root: {bool(E['readonly'])}; memory {E['memory_gib']} GiB; "
            f"{E['pids']} pids; {E['cpus']} CPUs; caps added {E['cap_add']}, dropped {E['cap_drop']}.",
            {"readonly": E["readonly"], "memory_gib": E["memory_gib"], "pids": E["pids"], "cpus": E["cpus"]})
    claim("edges", f"The swarm container runs on a read-only root filesystem with {E['memory_gib']:g} GiB of memory, {E['pids']} processes and {E['cpus']:g} CPUs at most.",
          "The container as podman configured it on 2026-10-29 (HYPDMZ_SWARM_* defaults).",
          [{"name": "memory, GiB", "key": "memory_gib", "value": E["memory_gib"]}, {"name": "process limit", "key": "pids", "value": E["pids"]},
           {"name": "CPUs", "key": "cpus", "value": E["cpus"]}])

    # ── the reviewer ──
    rj = rejudge_probes(P["results"])
    live = live_egress_check() if live else None
    if live is not None:
        lk = sum(1 for r in live["results"] if r["passed"])
        check.review(nodes["probes"]["claim"], "replicated" if (lk, len(live["results"])) == (P["all"]["k"], P["all"]["n"]) and rj == P["all"]["k"] else "objection",
                     method="Ran hypdmz egress-check --json again against the running pod, and re-judged the saved observations with the probe rules.",
                     notes=f"The second run passed {lk} of {len(live['results'])} probes, and re-judging the saved observations gives {rj} of {P['all']['n']}.")
    else:
        check.review(nodes["probes"]["claim"], "checked" if rj == P["all"]["k"] else "objection",
                     method="Re-judged the saved observations with the probe rules (blocked: no connection or an HTTP error; control: an answer) instead of trusting the flags.",
                     notes=f"Re-judged from the observations, {rj} of {P['all']['n']} probes pass.")
    R = regex_counts()
    check.review(nodes["key"]["claim"], "checked" if (R["calls"], R["injected"]) == (K["calls"]["n"], K["calls"]["k"]) else "objection",
                 method="Read proxy_events.jsonl as text and counted the chat-completion rows and their injected credential with a regex instead of a JSON parser.",
                 notes=f"Read as text, {R['injected']} of {R['calls']} chat-completion rows name model_api_key as injected.")
    check.review(nodes["cap"]["claim"], "checked" if R["limit"] == C["refused"] else "objection",
                 method="Counted `matched_rule: limit:` in the audit file as text.", notes=f"The audit file has {R['limit']} rows whose matched_rule starts with limit:.")
    W = rewalk_chain()
    check.review(nodes["chain"]["claim"], "replicated" if W["ok"] and W["events"] == H["events"] and W.get("head") == H["head"] else "objection",
                 method="Re-walked proxy_events.jsonl with an independent sha256 over each line's canonical JSON and the previous hash.",
                 notes=f"The independent walk found {W['events']} events, intact {W['ok']}, ending at head {W.get('head', '')[:16]}….")
    SR = swarms_from_records()
    check.review(nodes["swarms"]["claim"], "checked" if SR["complete"] == S["settled"]["k"] else "objection",
                 method="Loaded each swarm's bundle as a record and read its completion and its claims' review states instead of its telemetry.",
                 notes="From the records themselves: " + "; ".join(f"run {i + 1} complete {r['complete']}, {r['checked']} of {r['claims']} claims checked, {r['refused']} writes refused" for i, r in enumerate(SR["runs"])) + ".")
    inside = {r["name"]: r["passed"] for r in P["results"]}
    agree = bool(E["readonly"]) == inside.get("swarm-rootfs-readonly", False) and (E["memory_gib"] > 0) == inside.get("swarm-memory-capped", False) \
        and (E["pids"] > 0) == inside.get("swarm-pids-capped", False) and (E["cpus"] > 0) == inside.get("swarm-cpu-capped", False)
    check.review(nodes["edges"]["claim"], "checked" if agree else "objection",
                 method="Compared podman's HostConfig with what the four limit probes saw from inside the container (/proc/mounts and the cgroup files).",
                 notes=f"Seen from inside the container: root filesystem read-only {inside.get('swarm-rootfs-readonly')}, memory capped {inside.get('swarm-memory-capped')}, pids capped {inside.get('swarm-pids-capped')}, cpu capped {inside.get('swarm-cpu-capped')}.")

    facts = {"P": P, "K": K, "C": C, "H": H, "S": S, "E": E, "SR": SR, "live": live is not None}
    return g, inv, {"facts": facts, "nodes": nodes}


def fill(f: dict) -> dict:
    P, K, C, H, S, E = f["P"], f["K"], f["C"], f["H"], f["S"], f["E"]
    runs = " and ".join(f"{r['seconds']:.0f} s · {r['calls']} calls · ${r['usd']:.2f}" for r in S["runs"])
    return {
        "probes": f"{P['all']['k']} / {P['all']['n']}",
        "probes-s": f"{P['blocked']['k']} escape routes blocked · {P['limits']['k']} limits present · {P['controls']['k']} controls reachable · "
                    f"the console right {P['console']['k']} of {P['console']['n']} times",
        "injected": f"{K['calls']['k']} / {K['calls']['n']}",
        "injected-s": f"every model call since the pod was created; the {K['without_key_401']} without it were made before any key was vaulted and got a 401. "
                      f"The swarm's environment holds the placeholder, the proxy's holds {K['key_values_in_proxy_env']} key values",
        "swarms": f"{S['settled']['k']} / {S['settled']['n']}",
        "swarms-s": f"swarms settled inside the pod: {runs}",
        "chain": "intact" if H["ok"] else "BROKEN",
        "chain-events": f"{H['events']} events",
        "chain-s": f"{C['refused']} calls refused by the cap when it was set to one, each audited",
        "edges-s": f"read-only root · {E['memory_gib']:g} GiB · {E['pids']} pids · {E['cpus']:g} CPUs",
        "measured": "measured 2026-10-29",
        "probes-n": str(P["all"]["n"]),
    }


def page_text(values: dict) -> tuple[str, list[dict]]:
    body = PAGE.read_text(encoding="utf-8").split("<main", 1)[1].split("</main>", 1)[0]
    ok = [{"text": html.unescape(re.sub(r"<[^>]+>", "", m.group(2))), "why": html.unescape(m.group(1))}
          for m in re.finditer(r'<span data-ok="([^"]*)">(.*?)</span>', body, re.DOTALL)]
    body = re.sub(r'<span data-ok="[^"]*">(.*?)</span>', " ", body, flags=re.DOTALL)
    for m in re.finditer(r'<div class="t" data-example="([^"]*)">(.*?)</div>', body, re.DOTALL):
        ok.append({"text": html.unescape(re.sub(r"<[^>]+>", " ", m.group(2))).split("\n")[0].strip()[:70] + "…", "why": "illustration — " + html.unescape(m.group(1))})
    body = re.sub(r'<div class="t" data-example="[^"]*">.*?</div>', " ", body, flags=re.DOTALL)
    body = re.sub(r"<(script|pre|code|svg)\b.*?</\1>", " ", body, flags=re.DOTALL)
    for k, v in values.items():
        body = re.sub(rf'(<[^>]*data-fact="{k}"[^>]*>)[^<]*', lambda m, v=v: m.group(1) + v, body)
    text = re.sub(r"</(p|h1|h2|h3|li|div|td|th|tr|section|figcaption)>", "\n", body)
    text = html.unescape(re.sub(r"<[^>]+>", " ", text))
    text = "\n".join(re.sub(r"\s+", " ", ln).strip() for ln in text.splitlines())
    return re.sub(r"\n{2,}", "\n\n", text).strip() + "\n", ok


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--live", action="store_true", help="the reviewer also re-runs hypdmz egress-check against the running pod")
    a = ap.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    t0 = time.time()
    g, inv, built = build(a.live)
    values = fill(built["facts"])
    text, ok = page_text(values)
    lint = report_check.check(g, text, inv)
    b = g.export(inv)
    assert verify_bundle(b)["ok"]
    (SITE / "data").mkdir(exist_ok=True)
    (SITE / "data" / "site-record.bundle.json").write_text(json.dumps(b, ensure_ascii=False, separators=(",", ":")), encoding="utf-8", newline="\n")
    (SITE / "data" / "page-checked.md").write_text(
        "<!-- hypdmz.com's text as `hypgraph check` read it, figures filled in from the page's record (dev/site_record.py) -->\n\n" + text,
        encoding="utf-8", newline="\n")
    s = g.snapshot()
    standing = {}
    for key, n in built["nodes"].items():
        st = D.state(s, n["claim"])
        rv = st.get("review", {})
        standing[key] = {"code": n["code"], "id": n["claim"], "review": rv.get("state"),
                         "verdicts": rv.get("positive", []) + rv.get("negative", []),
                         "statement": s.nodes[n["claim"]]["body"].get("statement", ""), "summary": st.get("sentence", "")}
    g.close()
    S = built["facts"]["S"]
    runs = [{"key": "swarms", "label": f"The swarms' record ({S['settled']['n']} runs)", "path": f"data/evidence/{SWARM_BUNDLE}",
             "foot": "The record the swarms wrote to /records inside the pod, with their telemetry, exported with `hypgraph export --telemetry`: "
                     + "; ".join(f"run {i + 1} {r['seconds']:.0f} s, {r['calls']} model calls, ${r['usd']:.2f}" for i, r in enumerate(S["runs"]))
                     + ". Pick an investigation at the top; the Live view has every model and tool call in its lanes."}]
    data = {"facts": values, "standing": standing, "lint": lint, "data_ok": ok, "inv": inv, "built": now(), "head": b["head"],
            "runs": runs, "live": built["facts"]["live"]}
    (SITE / "assets" / "site-data.js").write_text("// generated by dev/site_record.py — do not edit\nwindow.SITE_DATA = "
                                                  + json.dumps(data, indent=1, ensure_ascii=False) + ";\n", encoding="utf-8", newline="\n")
    print(f"record: {len(b['events'])} events, {len(b['nodes'])} nodes, chain head {b['head'][:16]}…")
    for key, st in standing.items():
        print(f"  {st['code']:5} {key:8} {st['review']}")
    print(f"copy check: {lint['errors']} error(s), {lint['warnings']} warning(s), {lint['notes']} note(s); {len(ok)} phrase(s) true by design")
    for f in lint["findings"]:
        print(f"  line {f['line']} {f['level']}: {f['code']}: {f['excerpt'][:90]} — {f['message'][:140]}")
    print(f"({time.time() - t0:.0f} s)")
    sys.exit(1 if lint["errors"] else 0)


if __name__ == "__main__":
    main()
