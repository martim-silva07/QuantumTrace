from __future__ import annotations

from scanners.base import Finding

CRITICAL = "critical"
MEDIUM = "medium"
SAFE = "safe"
UNKNOWN = "unknown"

MIGRATE_KEM = "Migrate to ML-KEM (FIPS 203)"
MIGRATE_SIG = "Migrate to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)"
MIGRATE_AES256 = "Migrate to AES-256 (Grover margin)"
MIGRATE_HASH = "Migrate to SHA-256 or higher"
MIGRATE_TLS13 = "Upgrade to TLS 1.3 with hybrid key exchange (X25519MLKEM768)"

_SHOR_BROKEN = {
    "RSA", "DSA", "ECDSA", "ECDH", "ECDHE", "DH", "DHE", "ED25519", "ED448",
    "X25519", "X448", "SECP256R1", "SECP384R1", "P-256", "P-384", "P-521",
}
_LEGACY_BROKEN = {"MD5", "MD4", "MD2", "SHA1", "SHA-1", "DES", "3DES", "RC4", "RC2", "BLOWFISH", "SSL"}
_PQC = {"ML-KEM", "MLKEM", "KYBER", "ML-DSA", "MLDSA", "DILITHIUM", "SLH-DSA", "SLHDSA", "SPHINCS", "FALCON", "XMSS", "LMS"}
_STRONG_SYMMETRIC = {"AES-256", "CHACHA20", "SHA-384", "SHA-512", "SHA3", "SHA-3"}


def _normalize(algorithm: str) -> str:
    return algorithm.upper().replace("_", "-").strip()


def _classify_algorithm(f: Finding) -> tuple[str, str | None]:
    alg = _normalize(f.algorithm)

    if any(pqc in alg for pqc in ("MLKEM", "ML-KEM", "KYBER", "MLDSA", "ML-DSA")):
        return SAFE, None

    if alg in _PQC or any(alg.startswith(p) for p in _PQC):
        return SAFE, None

    if alg in _LEGACY_BROKEN:
        return CRITICAL, MIGRATE_HASH if "SHA" in alg or "MD" in alg else "Legacy algorithm: remove immediately"

    if alg in _SHOR_BROKEN or alg.startswith(("RSA", "EC", "DH", "DSA")):
        if f.primitive in ("signature",) or "DSA" in alg or "ED25519" in alg:
            return CRITICAL, MIGRATE_SIG
        return CRITICAL, MIGRATE_KEM

    if alg.startswith("AES"):
        if f.key_size is not None and f.key_size >= 256:
            return SAFE, None
        if f.key_size is not None and f.key_size <= 128:
            return MEDIUM, MIGRATE_AES256
        return MEDIUM, MIGRATE_AES256

    if any(alg.startswith(h) for h in _STRONG_SYMMETRIC):
        return SAFE, None

    if alg.startswith("SHA-2") or alg == "SHA-256" or alg.startswith("SHA256"):
        return SAFE, None

    return UNKNOWN, None


def _classify_protocol(f: Finding) -> tuple[str, str | None]:
    raw = (f.raw or f.algorithm).upper()
    if "TLSV1.3" in raw or "TLS 1.3" in raw or "TLS1.3" in raw:
        return MEDIUM, "Consider hybrid PQC key exchange (X25519MLKEM768)"
    if "TLSV1.2" in raw or "TLS 1.2" in raw or "TLS1.2" in raw:
        return MEDIUM, MIGRATE_TLS13
    return CRITICAL, MIGRATE_TLS13


def _classify_certificate(f: Finding) -> tuple[str, str | None]:
    tier, migration = _classify_algorithm(f)
    if tier == SAFE:
        return MEDIUM, "Classical certificate: plan a PQC migration when supported"
    return tier, migration


def classify(f: Finding) -> Finding:
    if f.asset_type == "protocol":
        tier, migration = _classify_protocol(f)
    elif f.asset_type == "certificate":
        tier, migration = _classify_certificate(f)
    else:
        tier, migration = _classify_algorithm(f)

    f.risk_tier = tier
    f.nist_migration = migration
    return f


def classify_all(findings: list[Finding]) -> list[Finding]:
    return [classify(f) for f in findings]
