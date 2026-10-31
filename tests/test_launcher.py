"""The launcher without podman: configuration, the package's payload, the policy seed, the command lines it would run."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from hypdmz import __version__, env, runner
from hypdmz.cli import main

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def state(tmp_path, monkeypatch):
    """A state dir of its own, with a .env that moves the ports off the defaults."""
    monkeypatch.setenv("HYPDMZ_STATE_DIR", str(tmp_path))
    for k in ("MODEL_API_KEY", "MODEL_BASE_URL", "MODEL"):
        monkeypatch.delenv(k, raising=False)
    (tmp_path / ".env").write_text("MODEL_BASE_URL=https://api.openai.com/v1\nMODEL=gpt-4o-mini\nHYPDMZ_UI_PORT=8100\n"
                                   "HYPDMZ_SWARM_MEMORY=2g\n", encoding="utf-8")
    return tmp_path


def test_version_matches_pyproject():
    txt = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r'^version = "(.+?)"$', txt, re.M).group(1) == __version__


def test_package_carries_its_payload():
    cfg = env.Config()
    for rel in ("controller/Dockerfile", "controller/apply-lockdown.sh", "proxy/Dockerfile", "proxy/app/main.py",
                "proxy/config/firewall.json", "swarm/Dockerfile", "swarm/entrypoint.sh", "swarm/probe_dns.py"):
        assert (cfg.images_dir / rel).is_file(), rel
    assert cfg.env_example.is_file()
    assert runner.bundled_examples(cfg) == ["first-swarm"]
    pol = json.loads(cfg.default_policy.read_text(encoding="utf-8"))
    assert pol["default_policy"] == "deny" and pol["limits"]["calls_per_hour"] > 0
    assert all(r.get("injects") == ["model_api_key"] for r in pol["rules"])


def test_shell_files_are_lf():
    cfg = env.Config()
    for f in cfg.images_dir.rglob("*"):
        if f.suffix == ".sh" or f.name == "Dockerfile":
            assert b"\r" not in f.read_bytes(), f"{f} has CRLF: the image would fail with 'No such file'"


def test_env_and_ports(state):
    cfg = env.load()
    assert cfg.state_dir == state
    assert cfg.model_base_url == "https://api.openai.com/v1" and cfg.model_host == "api.openai.com"
    assert cfg.model == "gpt-4o-mini"
    assert cfg.ui_port == 8100 and cfg.console_port == 8002 and cfg.proxy_port == 8080
    assert cfg.publish_ports == ((8100, 8000), (8002, 8002), (8080, 8080))
    assert cfg.swarm_memory == "2g" and cfg.swarm_cpus == "2" and cfg.swarm_pids == "512"
    assert cfg.key_secret == "hypdmz_llm_api_key"
    assert cfg.policy_path == state / "policy" / "firewall.json"


def test_process_env_overrides_file(state, monkeypatch):
    monkeypatch.setenv("MODEL", "other/model")
    assert env.load().model == "other/model"


def test_policy_is_seeded_once(state):
    cfg = env.load()
    assert runner.ensure_policy(cfg) is True
    seeded = cfg.policy_path.read_text(encoding="utf-8")
    assert seeded == cfg.default_policy.read_text(encoding="utf-8")
    cfg.policy_path.write_text(seeded.replace("1200", "7"), encoding="utf-8")
    assert runner.ensure_policy(cfg) is False                      # the operator's edit survives
    assert '"calls_per_hour": 7' in cfg.policy_path.read_text(encoding="utf-8")


def test_init_and_policy_commands(state, capsys):
    (state / ".env").unlink()
    assert main(["init"]) == 0
    assert (state / ".env").read_text(encoding="utf-8") == env.ENV_EXAMPLE.read_text(encoding="utf-8")
    assert (state / "policy" / "firewall.json").is_file()
    assert main(["policy", "path"]) == 0
    assert capsys.readouterr().out.strip().endswith(str(Path("policy") / "firewall.json"))
    assert main(["policy"]) == 0
    out = capsys.readouterr().out
    assert "model-api-deepinfra" in out and "injects model_api_key" in out
    (state / "policy" / "firewall.json").write_text("{not json", encoding="utf-8")
    assert main(["policy"]) == 1
    assert main(["policy", "reset"]) == 0
    assert (state / "policy" / "firewall.json.bak").read_text(encoding="utf-8") == "{not json"
    json.loads((state / "policy" / "firewall.json").read_text(encoding="utf-8"))


def test_example_copy(state, tmp_path, capsys):
    dest = tmp_path / "mine"
    assert main(["example", "first-swarm", str(dest)]) == 0
    assert (dest / "task.toml").is_file() and (dest / "scores.csv").is_file()
    assert main(["example", "nope"]) == 2
    assert main(["example"]) == 0
    assert "first-swarm" in capsys.readouterr().out


def test_up_dry_run_command_lines(state, capsys):
    """What `up` would run: the floor's capabilities, the proxy's mounts and secret, the swarm's edges."""
    assert main(["up", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "--publish 127.0.0.1:8100:8000" in out and "--publish 127.0.0.1:8002:8002" in out
    pod = next(ln for ln in out.splitlines() if "podman pod create" in ln)
    assert "--share net,uts" in pod                                       # no shared IPC namespace
    ctl = next(ln for ln in out.splitlines() if "--name hypdmz-controller" in ln)
    assert "--cap-add NET_ADMIN --cap-add NET_RAW" in ctl and ctl.endswith("hypdmz-controller:latest")
    proxy = next(ln for ln in out.splitlines() if "--name hypdmz-proxy" in ln)
    assert f"{state / 'policy'}:/app/config:ro" in proxy
    for flag in ("--cap-drop ALL", "--cap-add SETUID", "--cap-add SETGID", "--cap-add SETPCAP", "--cap-add CHOWN",
                 "--security-opt no-new-privileges", "--read-only", "--tmpfs /tmp:rw,size=64m,mode=1777"):
        assert flag in proxy, flag                                            # the proxy holds the key: hardened like the swarm
    assert "--cap-add NET" not in proxy
    assert "--secret hypdmz_llm_api_key,type=mount,uid=1001,gid=1001,mode=0400" in proxy
    assert "VAULT_BOOTSTRAP_MODEL_FILE=/run/secrets/hypdmz_llm_api_key" in proxy
    assert "VAULT_BOOTSTRAP_MODEL=" not in proxy.replace("VAULT_BOOTSTRAP_MODEL_HOST", "").replace("VAULT_BOOTSTRAP_MODEL_FILE", "")
    swarm = next(ln for ln in out.splitlines() if "--name hypdmz-swarm" in ln)
    for flag in ("--cap-drop ALL", "--cap-add SETUID", "--cap-add SETGID", "--cap-add CHOWN", "--security-opt no-new-privileges",
                 "--read-only", "--tmpfs /tmp:rw,size=2g,mode=1777", "--tmpfs /run/secrets:ro,size=4k,mode=0555", "--memory 2g --memory-swap 2g", "--cpus 2", "--pids-limit 512",
                 "OPENAI_API_KEY=__hypdmz_inject__", "HTTPS_PROXY=http://127.0.0.1:8080", "SSL_CERT_FILE=/tmp/hypdmz-ca-bundle.crt"):
        assert flag in swarm, flag
    assert f"{state / 'certs' / 'public'}:/etc/hypdmz-certs:ro" in swarm     # the certificate only, never the key
    assert "hypdmz_llm_api_key" not in swarm


def test_egress_probes_cover_the_claims():
    from hypdmz.egress import probes
    names = {p.name for p in probes(env.Config())}
    for n in ("direct-https-by-name", "direct-https-by-ip", "direct-ipv6", "direct-dns-public", "pod-resolver-dns",
              "proxy-control-api", "proxy-denies-unlisted", "proxy-relay-to-console", "ca-private-key", "run-secrets-empty",
              "swarm-code-write",
              "swarm-rootfs-readonly", "swarm-memory-capped", "swarm-pids-capped", "swarm-cpu-capped",
              "lockdown-gate", "record-ui", "proxy-listener", "proxy-upstream"):
        assert n in names, n


def test_module_entry_point():
    p = subprocess.run([sys.executable, "-m", "hypdmz", "--version"], capture_output=True, text=True, cwd=ROOT)
    assert p.returncode == 0 and __version__ in p.stdout


def test_swarm_image_pins_a_hypgraph_whose_serve_answers_browsers():
    """hypgraph < 0.7.7 answered 421 to every request when bound to 0.0.0.0, as the swarm image binds it."""
    df = (env.IMAGES_DIR / "swarm" / "Dockerfile").read_text(encoding="utf-8")
    pin = re.search(r"^ARG HYPGRAPH_VERSION=(\S+)$", df, re.M).group(1)
    assert tuple(int(x) for x in pin.split(".")[:3]) >= (0, 7, 7), pin
    assert "--host 0.0.0.0" in (env.IMAGES_DIR / "swarm" / "entrypoint.sh").read_text(encoding="utf-8")


def test_the_site_and_the_pod_run_the_same_hypgraph():
    """The page's record and UI are built with the hypgraph the swarm image installs, so what the site shows is what
    the pod serves."""
    df = (env.IMAGES_DIR / "swarm" / "Dockerfile").read_text(encoding="utf-8")
    pod = re.search(r"^ARG HYPGRAPH_VERSION=(\S+)$", df, re.M).group(1)
    pages = (ROOT / ".github" / "workflows" / "pages.yml").read_text(encoding="utf-8")
    site = re.search(r'pip install "hypgraph==([^"]+)"', pages).group(1)
    assert site == pod, (site, pod)


def test_ipc_namespace_check_reads_both_containers(monkeypatch):
    """The host-side probe: separate IPC namespaces pass, a shared one fails, an unreadable one is not a pass."""
    from hypdmz import egress
    ns = {}
    monkeypatch.setattr(egress, "_ns", lambda c, kind: ns.get(c, ""))
    ns.update({"hypdmz-swarm": "ipc:[4026532301]", "hypdmz-proxy": "ipc:[4026532302]"})
    assert [(r.name, r.passed, r.observed) for r in egress.namespace_checks()] == [("ipc-namespace-shared", True, "separate")]
    ns["hypdmz-proxy"] = "ipc:[4026532301]"
    assert egress.namespace_checks()[0].passed is False and egress.namespace_checks()[0].observed == "shared"
    ns["hypdmz-proxy"] = ""
    assert egress.namespace_checks()[0].passed is False and egress.namespace_checks()[0].observed == "missing"


def test_images_are_pinned_by_digest_and_proxy_packages_by_hash():
    for name in ("controller", "proxy", "swarm"):
        df = (env.IMAGES_DIR / name / "Dockerfile").read_text(encoding="utf-8")
        froms = [ln for ln in df.splitlines() if ln.startswith("FROM ")]
        assert froms and all("@sha256:" in ln for ln in froms), name
    df = (env.IMAGES_DIR / "proxy" / "Dockerfile").read_text(encoding="utf-8")
    assert "--require-hashes" in df
    req = (env.IMAGES_DIR / "proxy" / "requirements.txt").read_text(encoding="utf-8")
    pinned = [ln for ln in req.splitlines() if ln and not ln.startswith(("#", " ", "\\")) and "==" in ln]
    assert len(pinned) >= 20 and "fastapi==" in req and "cryptography==" in req
    assert req.count("--hash=sha256:") >= len(pinned)                           # at least one hash per pinned package


def test_proxy_checks_read_the_process(monkeypatch):
    from hypdmz import egress
    good = "uid|1001\ncaps|0000000000000000\nnnp|1\nrootfs|ro\n"
    monkeypatch.setattr(egress, "run_capture", lambda cmd: (0, good, ""))
    assert all(r.passed for r in egress.proxy_checks())
    bad = "uid|0\ncaps|000001ffffffffff\nnnp|0\nrootfs|rw\n"
    monkeypatch.setattr(egress, "run_capture", lambda cmd: (0, bad, ""))
    assert [r.passed for r in egress.proxy_checks()] == [False, False, False, False]
    monkeypatch.setattr(egress, "run_capture", lambda cmd: (1, "", "no such container"))
    assert not any(r.passed for r in egress.proxy_checks()) and egress.proxy_checks()[0].observed == "missing"


def test_a_probe_that_never_ran_is_a_failure_but_not_a_bypass():
    from hypdmz.egress import EgressReport, ProbeResult
    r = EgressReport("LOCKED", [ProbeResult("console-requires-token", "blocked", False, "missing", "")])
    assert not r.ok and not r.bypass_found
    r = EgressReport("LOCKED", [ProbeResult("direct-https-by-ip", "blocked", False, "200", "")])
    assert not r.ok and r.bypass_found
