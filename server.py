from __future__ import annotations

import json
import mimetypes
import shutil
from email.parser import BytesParser
from email.policy import default
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from classifier import classify_all
from scanners import ALL_SCANNERS

try:
    import db as dbmod
except Exception:
    dbmod = None

try:
    from scoring import compute_score
except ModuleNotFoundError:
    from Scoring import compute_score

ROOT = Path(__file__).resolve().parent
UPLOAD_DIR = ROOT / "tmp_uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

MONGO_ENABLED = False
MONGO_DB = None


def init_mongo():
    global MONGO_ENABLED, MONGO_DB
    if dbmod is None:
        return False
    try:
        client = dbmod.get_client()
        client.admin.command("ping")
        MONGO_DB = dbmod.get_db(client)
        dbmod.ensure_indexes(MONGO_DB)
        MONGO_ENABLED = True
        return True
    except Exception:
        MONGO_ENABLED = False
        MONGO_DB = None
        return False


def parse_multipart_parts(content_type: str, body: bytes):
    if not content_type.startswith("multipart/form-data"):
        return []
    header_block = f"Content-Type: {content_type}\r\n\r\n".encode("utf-8")
    message = BytesParser(policy=default).parsebytes(header_block + body)
    parts = []
    for part in message.iter_parts():
        filename = part.get_filename()
        if not filename:
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            payload = b""
        parts.append({"filename": filename, "content": payload})
    return parts


def detect_kind(name: str, sample: bytes | None = None) -> str:
    n = (name or "").lower()
    ext = Path(n).suffix.lower().lstrip(".")
    if sample:
        head = sample[:16]
        if head.startswith(b"PK\x03\x04") or head.startswith(b"\x1f\x8b") or head.startswith(b"BZh") or head.startswith(b"\xfd7zXZ\x00"):
            return "Archive"
        if head.startswith(b"\xd4\xc3\xb2\xa1") or head.startswith(b"\xa1\xb2\xc3\xd4") or head.startswith(b"\x4d\x3c\xb2\xa1"):
            return "Network capture"
        if head.startswith(b"-----BEGIN"):
            return "Certificate / key"
    if ext in {"pcap", "pcapng", "cap"}:
        return "Network capture"
    if ext in {"pem", "crt", "cer", "key", "der", "csr", "pub", "p12", "pfx"}:
        return "Certificate / key"
    if ext in {"zip", "tar", "tgz", "gz", "bz2", "xz", "jar"}:
        return "Archive"
    if ext in {"py", "java", "kt", "scala", "go", "js", "ts", "jsx", "tsx", "c", "h", "cpp", "cc", "hpp", "cs", "php", "rb", "rs"}:
        return "Source code"
    if ext in {"conf", "cnf", "ini", "yaml", "yml", "properties", "env", "tf", "toml", "cfg", "json"}:
        return "Configuration / cloud"
    if "nginx" in n or "haproxy" in n or "tls" in n:
        return "Configuration / cloud"
    return "Other file"


def scan_uploaded_file(path: Path) -> list[dict]:
    findings: list[dict] = []
    p = path
    kind = detect_kind(path.name, p.read_bytes()[:32])
    try:
        if kind == "Network capture":
            for scanner_name in ("network",):
                scanner_cls = ALL_SCANNERS[scanner_name]
                findings.extend(scanner_cls(str(p)).scan())
        else:
            for scanner_name in ("code", "cloud"):
                scanner_cls = ALL_SCANNERS[scanner_name]
                findings.extend(scanner_cls(str(p)).scan())
    except Exception:
        text = path.read_text(encoding="utf-8", errors="ignore")
        norms = {
            "RSA": "RSA",
            "ECDSA": "ECDSA",
            "ECDH": "ECDH",
            "AES": "AES",
            "SHA1": "SHA-1",
            "SHA256": "SHA-256",
            "TLS1.2": "TLS 1.2",
            "TLS1.3": "TLS 1.3",
            "ML-KEM": "ML-KEM",
        }
        for token, alg in norms.items():
            if token in text.upper():
                findings.append({
                    "source": "code" if kind == "Source code" else "cloud",
                    "asset_type": "algorithm",
                    "algorithm": alg,
                    "location": str(path),
                    "key_size": None,
                    "primitive": "protocol" if "TLS" in alg else "unknown",
                    "raw": token,
                    "risk_tier": None,
                    "nist_migration": None,
                })

    if findings:
        classified = classify_all([f if hasattr(f, "risk_tier") else _to_finding(f) for f in findings])
        return [f.to_dict() if hasattr(f, "to_dict") else f for f in classified]
    return []


def _to_finding(item: dict):
    from scanners.base import Finding
    return Finding(
        source=item.get("source", "code"),
        asset_type=item.get("asset_type", "algorithm"),
        algorithm=item.get("algorithm", "UNKNOWN"),
        location=item.get("location", "unknown"),
        key_size=item.get("key_size"),
        mode=item.get("mode"),
        primitive=item.get("primitive"),
        raw=item.get("raw"),
        context=item.get("context", {}),
    )


def build_scan_response(files: list[dict], findings: list[dict]) -> dict:
    stats = compute_score(findings)
    payload = {
        "summary": stats,
        "files": files,
        "findings": findings,
        "total_findings": len(findings),
    }
    if MONGO_ENABLED and MONGO_DB is not None:
        try:
            payload["mongo"] = {"status": "connected", "db": "Junctionx"}
        except Exception:
            pass
    else:
        payload["mongo"] = {"status": "offline", "db": "Junctionx"}
    return payload


class QuantumTraceHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in {"/", "/index.html"}:
            self.serve_file(ROOT / "index.html")
            return
        if parsed.path in {"/Script", "/script"}:
            self.serve_file(ROOT / "Script")
            return
        if parsed.path == "/api/health":
            self.send_json({"status": "ok", "service": "QuantumTrace"})
            return
        self.send_error(404)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/scan":
            self.handle_scan()
            return
        self.send_error(404)

    def handle_scan(self):
        try:
            content_type = self.headers.get("Content-Type", "")
            if not content_type.startswith("multipart/form-data"):
                self.send_json({"error": "Expected multipart/form-data"}, status=400)
                return

            content_length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(content_length)
            uploaded_items = parse_multipart_parts(content_type, body)
            uploaded = []
            for item in uploaded_items:
                filename = item["filename"]
                content = item["content"]
                target = UPLOAD_DIR / filename
                target.write_bytes(content)
                uploaded.append({
                    "name": filename,
                    "type": detect_kind(filename, content[:32]),
                    "size": len(content),
                })

            if not uploaded:
                self.send_json({"error": "No files were uploaded"}, status=400)
                return

            findings = []
            for f in uploaded:
                try:
                    p = UPLOAD_DIR / f["name"]
                    findings.extend(scan_uploaded_file(p))
                except Exception as exc:
                    findings.append({
                        "source": "system",
                        "asset_type": "algorithm",
                        "algorithm": "SCAN-ERROR",
                        "location": f["name"],
                        "key_size": None,
                        "primitive": "unknown",
                        "raw": str(exc),
                        "risk_tier": "unknown",
                        "nist_migration": None,
                    })

            if MONGO_ENABLED and MONGO_DB is not None:
                try:
                    scan_id = dbmod.start_scan(MONGO_DB, ["code", "cloud"], str(ROOT))
                    dbmod.finish_scan(MONGO_DB, scan_id, [
                        _to_finding(f) for f in findings
                    ], build_scan_response(uploaded, findings)["summary"], status="completed")
                except Exception:
                    pass

            payload = build_scan_response(uploaded, findings)
            self.send_json(payload)
        except Exception as exc:
            self.send_json({"error": str(exc)}, status=500)

    def serve_file(self, path: Path):
        if not path.exists():
            self.send_error(404, "Not found")
            return
        mime, _ = mimetypes.guess_type(str(path))
        if path.name.lower().endswith('.html') or path.name.lower() == 'script':
            mime = 'text/html; charset=utf-8'
        self.send_response(200)
        self.send_header("Content-Type", mime or "text/html; charset=utf-8")
        self.send_header("Content-Length", str(path.stat().st_size))
        self.end_headers()
        with path.open("rb") as fh:
            shutil.copyfileobj(fh, self.wfile)

    def send_json(self, payload: dict, status: int = 200):
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_server(host: str = "0.0.0.0", port: int = 8000):
    server = ThreadingHTTPServer((host, port), QuantumTraceHandler)
    print(f"QuantumTrace server running at http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run_server()
