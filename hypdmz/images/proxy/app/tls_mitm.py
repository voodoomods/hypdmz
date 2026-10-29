"""
TLS MITM — leaf cert minter and SSL contexts.

Loads the HypDMZ egress CA from HYPDMZ_CA_PEM (cert + private key concatenated
in one PEM; `python -m app.tls_mitm init DIR` creates one). Mints per-SNI leaf
certs on demand, signs them with the CA, caches contexts in memory and
PEM files in HYPDMZ_LEAF_CACHE for restart-survival.

Security:
  - The CA private key never leaves the proxy container.
  - Leaf cache is in /app/data (proxy-only writable mount).
  - Leaf cert validity is capped at 825 days (CAB Forum baseline).
  - Only hostnames the firewall has approved should ever be passed in;
    enforce that at the call site, not here.
"""

import hashlib
import os
import ssl
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


CA_PEM_PATH    = os.getenv("HYPDMZ_CA_PEM",       "/etc/hypdmz-certs/hypdmz-ca.pem")
LEAF_CACHE_DIR = os.getenv("HYPDMZ_LEAF_CACHE",   "/app/data/leaf-certs")
LEAF_KEY_BITS  = int(os.getenv("HYPDMZ_LEAF_BITS", "2048"))

# Bump when the leaf-cert format changes so old cached files get re-minted
# without operator intervention.
#   v1 — initial
#   v2 — adds SKI/AKI/KeyUsage (strict X.509 chain verification)
#   v3 — the chain file carries the CA after the leaf, so clients that pin the CA by key (the agent's headless
#        Chromium, --ignore-certificate-errors-spki-list) can match it; leaf-only chains gave "certificate unknown"
LEAF_SCHEMA = "v3"

_lock = threading.Lock()
_ca_cert: x509.Certificate | None = None
_ca_key = None
_leaf_ctx_cache: dict[str, ssl.SSLContext] = {}
_upstream_ctx: ssl.SSLContext | None = None


def _load_ca() -> None:
    global _ca_cert, _ca_key
    if _ca_cert is not None:
        return
    pem = Path(CA_PEM_PATH).read_bytes()
    _ca_key  = serialization.load_pem_private_key(pem, password=None, backend=default_backend())
    _ca_cert = x509.load_pem_x509_certificate(pem, backend=default_backend())


def ca_fingerprint() -> str:
    """SHA-256 fingerprint of the CA cert — handy for the UI banner."""
    _load_ca()
    return _ca_cert.fingerprint(hashes.SHA256()).hex()


def is_available() -> bool:
    try:
        _load_ca()
        return True
    except Exception:
        return False


def _authority_key_identifier() -> x509.AuthorityKeyIdentifier:
    """Build AKI from the CA's Subject Key Identifier if present, else from
    the CA public key. our CA carries SKI; falling back to pubkey-derived
    keeps us correct against any CA layout."""
    try:
        ca_ski = _ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        return x509.AuthorityKeyIdentifier(
            key_identifier=ca_ski.digest,
            authority_cert_issuer=None,
            authority_cert_serial_number=None,
        )
    except x509.ExtensionNotFound:
        return x509.AuthorityKeyIdentifier.from_issuer_public_key(_ca_cert.public_key())


def _mint_leaf_pem(hostname: str) -> tuple[bytes, bytes]:
    _load_ca()
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=LEAF_KEY_BITS, backend=default_backend())
    now = datetime.now(timezone.utc)
    san = [x509.DNSName(hostname)]
    # If the hostname looks like an IP, also include it as IPAddress SAN.
    try:
        import ipaddress
        ip = ipaddress.ip_address(hostname)
        san.append(x509.IPAddress(ip))
    except ValueError:
        pass

    leaf_pub = leaf_key.public_key()
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(_ca_cert.subject)
        .public_key(leaf_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        # ── X.509 v3 chain linkage (required by strict verifiers) ──
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_pub), critical=False)
        .add_extension(_authority_key_identifier(), critical=False)
        # KeyUsage: digitalSignature + keyEncipherment cover RSA TLS server certs.
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True,
                content_commitment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
    )
    cert = builder.sign(_ca_key, hashes.SHA256(), backend=default_backend())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem  = leaf_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem + _ca_cert.public_bytes(serialization.Encoding.PEM), key_pem


def get_leaf_context(hostname: str) -> ssl.SSLContext:
    """Return an SSLContext that serves a leaf cert for `hostname`."""
    with _lock:
        ctx = _leaf_ctx_cache.get(hostname)
        if ctx is not None:
            return ctx

        cache_dir = Path(LEAF_CACHE_DIR)
        cache_dir.mkdir(parents=True, exist_ok=True)
        h = hashlib.sha256(hostname.encode("utf-8")).hexdigest()[:32]
        leaf_path = cache_dir / f"{LEAF_SCHEMA}-{h}.crt"
        key_path  = cache_dir / f"{LEAF_SCHEMA}-{h}.key"

        if not (leaf_path.exists() and key_path.exists()):
            cert_pem, key_pem = _mint_leaf_pem(hostname)
            leaf_path.write_bytes(cert_pem)
            key_path.write_bytes(key_pem)
            try:
                os.chmod(key_path, 0o600)
            except Exception:
                pass

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(leaf_path), keyfile=str(key_path))
        ctx.set_alpn_protocols(["http/1.1"])  # HTTP/2 deferred — Phase 5
        _leaf_ctx_cache[hostname] = ctx
        return ctx


def upstream_context() -> ssl.SSLContext:
    """SSLContext for outbound TLS to the real server."""
    global _upstream_ctx
    if _upstream_ctx is None:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["http/1.1"])
        _upstream_ctx = ctx
    return _upstream_ctx


# ── CA creation (run once by the launcher, before the pod starts) ──────────

CA_FILE = "hypdmz-ca.pem"            # cert + key: the proxy's secret (mode 0600, owned by the proxy UID)
CA_CERT_FILE = "hypdmz-ca-cert.pem"  # cert only, in DIR/public/: what the swarm container and the host trust


def init_ca(directory: str, *, days: int = 3650, bits: int = 2048) -> Path:
    """Create the HypDMZ egress CA in `directory` unless it exists. Returns the cert+key path.

    The private key stays in `directory`, which only the proxy container mounts; the swarm
    container mounts `directory/public`, which holds the certificate alone."""
    d = Path(directory)
    pub = d / "public"
    pub.mkdir(parents=True, exist_ok=True)
    pem_path, cert_path = d / CA_FILE, pub / CA_CERT_FILE
    if pem_path.exists() and cert_path.exists():
        return pem_path
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits, backend=default_backend())
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "HypDMZ Egress CA"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "HypDMZ")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            key_encipherment=False, content_commitment=False, data_encipherment=False,
            key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256(), backend=default_backend())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption())
    tmp = pem_path.with_suffix(".tmp")
    tmp.write_bytes(cert_pem + key_pem)
    uid = int(os.getenv("HYPDMZ_PROXY_UID", "1001"))
    for fn in (lambda: os.chmod(tmp, 0o600), lambda: os.chown(tmp, uid, uid)):
        try:
            fn()
        except Exception:
            pass                                   # Windows / macOS mounts ignore ownership
    tmp.replace(pem_path)
    cert_path.write_bytes(cert_pem)
    try:
        os.chmod(cert_path, 0o644)
    except Exception:
        pass
    print(f"[tls] created CA sha256:{cert.fingerprint(hashes.SHA256()).hex()} in {d}")
    return pem_path


if __name__ == "__main__":  # python -m app.tls_mitm init /certs
    import sys
    if len(sys.argv) >= 3 and sys.argv[1] == "init":
        init_ca(sys.argv[2])
    else:
        print("usage: python -m app.tls_mitm init DIR", file=sys.stderr)
        sys.exit(2)
