from __future__ import annotations

import json
import mimetypes
import os
import re
import shutil
import subprocess
import time
import uuid
import zipfile
from datetime import datetime
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

from parser import build_report
from excel_export import export_report_xlsx


ROOT = Path(__file__).resolve().parent
UPLOADS = ROOT / "uploads"
EXTRACTED = ROOT / "work" / "extracted"
REPORTS = ROOT / "reports"
STATIC_FILES = {"", "index.html", "app.js", "styles.css", "report-data.js"}
MAX_UPLOAD_BYTES = 4 * 1024 * 1024 * 1024


def ensure_dirs() -> None:
    UPLOADS.mkdir(exist_ok=True)
    EXTRACTED.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(exist_ok=True)


def find_7za() -> str | None:
    for name in ["7za", "7z", "7zr"]:
        found = shutil.which(name)
        if found:
            return found
    candidates = [
        Path(r"C:\Program Files\7-Zip\7z.exe"),
        Path(r"C:\Program Files (x86)\7-Zip\7z.exe"),
        Path(r"C:\Program Files (x86)\VMware\VMware Workstation\7za.exe"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return None


def safe_relative_name(name: str) -> Path:
    name = name.replace("\\", "/").strip("/")
    parts = [part for part in name.split("/") if part and part not in {".", ".."}]
    return Path(*parts) if parts else Path(f"upload-{uuid.uuid4().hex}")


def parse_multipart(body: bytes, content_type: str) -> list[tuple[str, bytes]]:
    match = re.search(r"boundary=(?:\"([^\"]+)\"|([^;]+))", content_type)
    if not match:
        raise ValueError("multipart boundary not found")
    boundary = (match.group(1) or match.group(2)).encode()
    parts: list[tuple[str, bytes]] = []
    delimiter = b"--" + boundary

    for raw_part in body.split(delimiter):
        raw_part = raw_part.strip(b"\r\n")
        if not raw_part or raw_part == b"--":
            continue
        if b"\r\n\r\n" not in raw_part:
            continue
        header_blob, data = raw_part.split(b"\r\n\r\n", 1)
        headers = header_blob.decode("latin-1", errors="replace")
        filename_match = re.search(r'filename="([^"]*)"', headers)
        if not filename_match:
            continue
        filename = filename_match.group(1).encode("latin-1", errors="replace").decode("utf-8", errors="replace")
        if filename:
            parts.append((filename, data.rstrip(b"\r\n")))
    return parts


def extract_archive(path: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    suffix = path.suffix.lower()
    if suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            archive.extractall(destination)
        return
    if suffix == ".7z":
        exe = find_7za()
        if not exe:
            raise RuntimeError("7z/7za executable not found. Install 7-Zip or upload an extracted AutoSupport folder.")
        command = [exe, "x", str(path), f"-o{destination}", "-y"]
        result = subprocess.run(command, capture_output=True, text=True, timeout=600)
        if result.returncode != 0:
            raise RuntimeError(result.stderr or result.stdout or "7z extraction failed")
        return
    raise RuntimeError(f"Unsupported archive type: {path.name}")


def discover_asup_folders(root: Path) -> list[Path]:
    folders = []
    for path in root.rglob("system-info.xml"):
        folder = path.parent
        if (folder / "CLUSTER-INFO.xml").exists():
            folders.append(folder)
    return sorted(set(folders), key=lambda item: str(item).lower())


def report_filename(report: dict) -> Path:
    cluster = report.get("cluster", {}).get("name") or "autosupport"
    clean_cluster = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(cluster)).strip("_") or "autosupport"
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return REPORTS / f"{stamp}_{clean_cluster}_{uuid.uuid4().hex[:8]}.json"


def write_json_report(report: dict, source_names: list[str]) -> Path:
    report["id"] = uuid.uuid4().hex
    report["savedAt"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report["sourceNames"] = source_names
    report["storageMode"] = "json-only"
    path = report_filename(report)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def report_summary(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    return {
        "file": path.name,
        "path": str(path),
        "reportsDir": str(REPORTS),
        "id": data.get("id"),
        "cluster": data.get("cluster", {}).get("name", "-"),
        "generatedAt": data.get("generatedAt", "-"),
        "savedAt": data.get("savedAt", "-"),
        "nodes": len(data.get("nodes", [])),
        "volumes": len(data.get("volumes", [])),
        "disks": data.get("disks", {}).get("total", 0),
        "protocols": data.get("cluster", {}).get("protocols", []),
        "sourceNames": data.get("sourceNames", []),
    }


class Handler(SimpleHTTPRequestHandler):
    server_version = "NetAppASUPAnalyzer/0.3"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        if path == "/api/reports":
            self.send_json(self.list_reports())
            return
        if path == "/api/storage":
            ensure_dirs()
            self.send_json({"reportsDir": str(REPORTS), "reportsCount": len(list(REPORTS.glob("*.json")))})
            return
        if path.startswith("/api/reports/"):
            self.send_report(path.rsplit("/", 1)[-1])
            return
        if path == "/":
            self.serve_file(ROOT / "index.html")
            return
        name = path.lstrip("/")
        if name in STATIC_FILES:
            self.serve_file(ROOT / (name or "index.html"))
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_DELETE(self) -> None:
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        if path.startswith("/api/reports/"):
            self.delete_report(path.rsplit("/", 1)[-1])
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            if path == "/api/upload":
                self.handle_upload()
                return
            if path == "/api/export/excel":
                self.handle_excel_export()
                return
            self.send_error(HTTPStatus.NOT_FOUND)
        except Exception as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def handle_upload(self) -> None:
        ensure_dirs()
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            raise ValueError("No upload body")
        if length > MAX_UPLOAD_BYTES:
            raise ValueError("Upload is too large")
        content_type = self.headers.get("Content-Type", "")
        body = self.rfile.read(length)
        parts = parse_multipart(body, content_type)
        if not parts:
            raise ValueError("No files uploaded")

        batch = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
        upload_root = UPLOADS / batch
        extract_root = EXTRACTED / batch
        upload_root.mkdir(parents=True)
        extract_root.mkdir(parents=True)

        source_names: list[str] = []
        try:
            for filename, data in parts:
                relative = safe_relative_name(filename)
                target = upload_root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                source_names.append(filename)
                if target.suffix.lower() in {".7z", ".zip"}:
                    extract_archive(target, extract_root / target.stem)

            folder_upload_roots = [upload_root]
            candidate_folders = discover_asup_folders(extract_root)
            candidate_folders.extend(discover_asup_folders(upload_root))
            if not candidate_folders:
                raise RuntimeError("AutoSupport folder not found. Upload .7z/.zip files or an extracted folder containing system-info.xml.")

            report = build_report(candidate_folders)
            report["sourceFolders"] = source_names
            saved = write_json_report(report, source_names)
            payload = json.loads(saved.read_text(encoding="utf-8"))
        finally:
            shutil.rmtree(upload_root, ignore_errors=True)
            shutil.rmtree(extract_root, ignore_errors=True)

        summary = report_summary(saved)
        self.send_json({
            "report": payload,
            "summary": summary,
            "storage": {"reportsDir": str(REPORTS), "savedFile": str(saved)},
        })

    def handle_excel_export(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            raise ValueError("No report data")
        if length > MAX_UPLOAD_BYTES:
            raise ValueError("Report data is too large")
        report = json.loads(self.rfile.read(length).decode("utf-8"))
        data = export_report_xlsx(report)
        cluster = report.get("cluster", {}).get("name") or "autosupport"
        clean_cluster = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(cluster)).strip("_") or "autosupport"
        filename = f"{clean_cluster}-autosupport-report.xlsx"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def list_reports(self) -> list[dict]:
        ensure_dirs()
        paths = sorted(REPORTS.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True)
        summaries = []
        for path in paths:
            try:
                summaries.append(report_summary(path))
            except (json.JSONDecodeError, OSError):
                continue
        return summaries

    def delete_report(self, filename: str) -> None:
        safe = Path(filename).name
        path = REPORTS / safe
        if not path.exists() or path.suffix.lower() != ".json":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        path.unlink()
        self.send_json({"deleted": safe, "reports": self.list_reports()})

    def send_report(self, filename: str) -> None:
        safe = Path(filename).name
        path = REPORTS / safe
        if not path.exists() or path.suffix.lower() != ".json":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self.serve_file(path, "application/json; charset=utf-8")

    def serve_file(self, path: Path, content_type: str | None = None) -> None:
        if not path.exists() or not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        data = path.read_bytes()
        guessed = content_type or mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        if guessed.startswith("text/") or path.suffix in {".js", ".css", ".html"}:
            guessed += "; charset=utf-8"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", guessed)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, payload, status: HTTPStatus = HTTPStatus.OK) -> None:
        data = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args) -> None:
        print("[%s] %s" % (time.strftime("%H:%M:%S"), format % args))


def main() -> None:
    ensure_dirs()
    os.chdir(ROOT)
    server = ThreadingHTTPServer(("0.0.0.0", 8765), Handler)
    print("NetApp AutoSupport Analyzer")
    print("Open: http://127.0.0.1:8765")
    print("Reports folder:", REPORTS)
    print("Stop: press Ctrl+C")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
