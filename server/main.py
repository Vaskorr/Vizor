from __future__ import annotations

import io
import ipaddress
import json
import os
import re
import shlex
import sqlite3
import subprocess
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

DATA_DIR = Path(os.getenv("VIZOR_DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "vizor.db"
SCANS_DIR = DATA_DIR / "scans"
MAX_XML_BYTES = 100 * 1024 * 1024
MAX_FLAGS_LENGTH = 1000
SAFE_NMAP_SWITCHES = {
    "-sS", "-sT", "-sU", "-sV", "-O", "-Pn", "-n", "-R", "-F",
    "--open", "--reason", "--version-light", "--version-all", "--traceroute",
    "--packet-trace", "--disable-arp-ping", "--send-ip", "--send-eth",
}
SAFE_INTEGER_FLAGS = {
    "--top-ports": (1, 65535),
    "--max-retries": (0, 20),
    "--min-rate": (1, 1_000_000),
    "--max-rate": (1, 1_000_000),
    "--min-hostgroup": (1, 65535),
    "--max-hostgroup": (1, 65535),
    "--min-parallelism": (1, 65535),
    "--max-parallelism": (1, 65535),
    "--version-intensity": (0, 9),
}
SAFE_DURATION_FLAGS = {"--host-timeout", "--scan-delay", "--max-scan-delay", "--script-timeout"}
PORT_SPEC_PATTERN = re.compile(r"^(?:[TU]:)?[0-9,-]+(?:,(?:[TU]:)?[0-9,-]+)*$")
DURATION_PATTERN = re.compile(r"^[1-9][0-9]*(?:ms|s|m|h)?$")
SCRIPT_SELECTOR_PATTERN = re.compile(r"^[A-Za-z0-9_-]+(?:,[A-Za-z0-9_-]+)*$")
DEFAULT_SETTINGS = {
    "speed": "T3",
    "exclusions": "",
    "flags": "-sV --reason",
    "scripts": "default,safe",
    "schedule_enabled": True,
    "day": "monday",
    "time": "11:00",
}

@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    threading.Thread(target=scheduler_loop, name="vizor-scheduler", daemon=True).start()
    yield


app = FastAPI(title="Vizor API", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in os.getenv("VIZOR_CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",") if origin.strip()],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    segment_id: str = Field(min_length=1, max_length=80)


class SegmentPayload(BaseModel):
    id: str = Field(min_length=1, max_length=80)
    name: str = Field(min_length=1, max_length=160)
    cidrs: str = Field(min_length=1, max_length=2000)
    enabled: bool = True


class SettingsPayload(BaseModel):
    segments: list[SegmentPayload] | None = None
    speed: str = "T3"
    exclusions: str = ""
    flags: str = "-sV --reason"
    scripts: str = "default,safe"
    day: str = "monday"
    time: str = "11:00"
    schedule_enabled: bool = True


@contextmanager
def db():
    connection = sqlite3.connect(DB_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SCANS_DIR.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS segments (
              id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              targets TEXT NOT NULL,
              enabled INTEGER NOT NULL DEFAULT 1,
              last_scan_at TEXT
            );
            CREATE TABLE IF NOT EXISTS settings (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scans (
              id TEXT PRIMARY KEY,
              segment_id TEXT NOT NULL,
              started_at TEXT NOT NULL,
              finished_at TEXT,
              duration_seconds REAL,
              status TEXT NOT NULL,
              xml_path TEXT,
              error TEXT,
              FOREIGN KEY(segment_id) REFERENCES segments(id)
            );
            CREATE TABLE IF NOT EXISTS hosts (
              id INTEGER PRIMARY KEY,
              scan_id TEXT NOT NULL,
              address TEXT NOT NULL,
              hostname TEXT,
              state TEXT,
              FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS ports (
              id INTEGER PRIMARY KEY,
              host_id INTEGER NOT NULL,
              port INTEGER NOT NULL,
              protocol TEXT NOT NULL,
              state TEXT,
              service TEXT,
              product TEXT,
              version TEXT,
              banner TEXT,
              FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS scripts (
              id INTEGER PRIMARY KEY,
              host_id INTEGER NOT NULL,
              port_id INTEGER,
              script_id TEXT NOT NULL,
              output TEXT,
              FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE,
              FOREIGN KEY(port_id) REFERENCES ports(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_scans_segment_started ON scans(segment_id, started_at DESC);
            CREATE INDEX IF NOT EXISTS idx_hosts_scan_address ON hosts(scan_id, address);
            CREATE INDEX IF NOT EXISTS idx_ports_host_port ON ports(host_id, port, protocol);
            CREATE INDEX IF NOT EXISTS idx_ports_service ON ports(service);
            CREATE INDEX IF NOT EXISTS idx_scripts_script_id ON scripts(script_id);
            """
        )
        conn.executemany(
            "INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)",
            [(key, json.dumps(value, ensure_ascii=False)) for key, value in DEFAULT_SETTINGS.items()],
        )
        conn.execute("PRAGMA optimize")


def load_settings(conn: sqlite3.Connection | None = None) -> dict[str, Any]:
    owns = conn is None
    if owns:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
    assert conn is not None
    values = dict(DEFAULT_SETTINGS)
    for row in conn.execute("SELECT key, value FROM settings"):
        try:
            values[row["key"]] = json.loads(row["value"])
        except json.JSONDecodeError:
            values[row["key"]] = row["value"]
    if owns:
        conn.close()
    return values


def normalize_targets(raw: str) -> list[str]:
    targets = [part.strip() for part in raw.replace("\n", ",").split(",") if part.strip()]
    if not targets:
        raise ValueError("Некорректная цель сканирования")
    for value in targets:
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError(f"Разрешены только IP-адреса и CIDR-сети: {value}") from exc
    return targets


def parse_safe_nmap_flags(raw: str) -> list[str]:
    if len(raw) > MAX_FLAGS_LENGTH:
        raise ValueError("Строка флагов Nmap слишком длинная")
    if any(ord(char) < 32 for char in raw) or any(char in raw for char in ";&|`$<>\\{}"):
        raise ValueError("Строка флагов содержит запрещённые символы")
    try:
        tokens = shlex.split(raw, posix=True)
    except ValueError as exc:
        raise ValueError("Не удалось разобрать строку флагов Nmap") from exc

    safe: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in SAFE_NMAP_SWITCHES:
            safe.append(token)
            index += 1
            continue

        flag = token
        inline_value: str | None = None
        if "=" in token:
            flag, inline_value = token.split("=", 1)
        elif token.startswith("-p") and token != "-p":
            flag, inline_value = "-p", token[2:]

        if flag == "-p" or flag in SAFE_INTEGER_FLAGS or flag in SAFE_DURATION_FLAGS:
            if inline_value is None:
                index += 1
                if index >= len(tokens):
                    raise ValueError(f"Для {flag} требуется значение")
                inline_value = tokens[index]

            if flag == "-p":
                if not PORT_SPEC_PATTERN.fullmatch(inline_value):
                    raise ValueError("Некорректная спецификация портов")
            elif flag in SAFE_INTEGER_FLAGS:
                if not inline_value.isdigit():
                    raise ValueError(f"Для {flag} требуется целое число")
                minimum, maximum = SAFE_INTEGER_FLAGS[flag]
                if not minimum <= int(inline_value) <= maximum:
                    raise ValueError(f"Значение {flag} должно быть от {minimum} до {maximum}")
            elif not DURATION_PATTERN.fullmatch(inline_value):
                raise ValueError(f"Некорректное значение времени для {flag}")

            safe.extend([flag, inline_value])
            index += 1
            continue

        raise ValueError(f"Флаг Nmap не разрешён: {token}")
    return safe


def validate_script_selector(raw: str) -> str:
    value = raw.strip()
    if not value:
        return ""
    if len(value) > 500 or not SCRIPT_SELECTOR_PATTERN.fullmatch(value):
        raise ValueError("NSE допускает только категории и имена скриптов через запятую")
    return value


def build_nmap_command(targets: str, xml_path: Path, settings: dict[str, Any]) -> list[str]:
    speed = str(settings.get("speed", "T3")).upper()
    if speed not in {"T1", "T2", "T3", "T4", "T5"}:
        raise ValueError("Некорректный timing template")
    command = ["nmap", f"-{speed}"]
    command.extend(parse_safe_nmap_flags(str(settings.get("flags", "-sV --reason"))))
    scripts = validate_script_selector(str(settings.get("scripts", "")))
    if scripts:
        command.extend(["--script", scripts])
    exclusions = str(settings.get("exclusions", "")).strip()
    if exclusions:
        command.extend(["--exclude", ",".join(normalize_targets(exclusions))])
    command.extend(["-oX", str(xml_path), *normalize_targets(targets)])
    return command


def parse_xml_into_db(scan_id: str, xml_path: Path) -> dict[str, int]:
    try:
        root = ET.parse(xml_path).getroot()
    except (ET.ParseError, OSError) as exc:
        raise ValueError(f"Не удалось разобрать XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise ValueError("Корневой элемент XML должен быть nmaprun")
    host_count = port_count = script_count = 0
    with db() as conn:
        conn.execute("DELETE FROM hosts WHERE scan_id = ?", (scan_id,))
        for host in root.findall("host"):
            address_node = host.find("address[@addrtype='ipv4']")
            if address_node is None:
                address_node = host.find("address")
            if address_node is None:
                continue
            hostname_node = host.find("hostnames/hostname")
            state_node = host.find("status")
            host_cursor = conn.execute(
                "INSERT INTO hosts(scan_id, address, hostname, state) VALUES (?, ?, ?, ?)",
                (scan_id, address_node.get("addr", "unknown"), hostname_node.get("name", "") if hostname_node is not None else "", state_node.get("state", "unknown") if state_node is not None else "unknown"),
            )
            host_id = host_cursor.lastrowid
            host_count += 1
            for script in host.findall("hostscript/script"):
                conn.execute("INSERT INTO scripts(host_id, port_id, script_id, output) VALUES (?, NULL, ?, ?)", (host_id, script.get("id", "script"), script.get("output", "")))
                script_count += 1
            for port in host.findall("ports/port"):
                service = port.find("service")
                state = port.find("state")
                product = service.get("product", "") if service is not None else ""
                version = service.get("version", "") if service is not None else ""
                extra = service.get("extrainfo", "") if service is not None else ""
                banner = " ".join(filter(None, (product, version, extra)))
                port_cursor = conn.execute(
                    """INSERT INTO ports(host_id, port, protocol, state, service, product, version, banner)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (host_id, int(port.get("portid", 0)), port.get("protocol", "tcp"), state.get("state", "unknown") if state is not None else "unknown", service.get("name", "unknown") if service is not None else "unknown", product, version, banner),
                )
                port_id = port_cursor.lastrowid
                port_count += 1
                for script in port.findall("script"):
                    conn.execute("INSERT INTO scripts(host_id, port_id, script_id, output) VALUES (?, ?, ?, ?)", (host_id, port_id, script.get("id", "script"), script.get("output", "")))
                    script_count += 1
    return {"hosts": host_count, "ports": port_count, "scripts": script_count}


def execute_scan(scan_id: str, segment_id: str) -> None:
    started = time.monotonic()
    xml_path = SCANS_DIR / f"{scan_id}.xml"
    try:
        with db() as conn:
            segment = conn.execute("SELECT targets FROM segments WHERE id = ? AND enabled = 1", (segment_id,)).fetchone()
            if not segment:
                raise ValueError("Сегмент не найден или отключён")
            command = build_nmap_command(segment["targets"], xml_path, load_settings(conn))
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=7200,
            check=False,
            shell=False,
            cwd=SCANS_DIR,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": "/nonexistent"},
        )
        if completed.returncode != 0:
            raise RuntimeError((completed.stderr or completed.stdout or "Nmap завершился с ошибкой")[-4000:])
        parse_xml_into_db(scan_id, xml_path)
        finished = now_iso()
        with db() as conn:
            conn.execute("UPDATE scans SET status='success', finished_at=?, duration_seconds=?, xml_path=? WHERE id=?", (finished, round(time.monotonic() - started, 2), str(xml_path), scan_id))
            conn.execute("UPDATE segments SET last_scan_at=? WHERE id=?", (finished, segment_id))
    except Exception as exc:  # recorded for the operator; background job must not vanish
        with db() as conn:
            conn.execute("UPDATE scans SET status='failed', finished_at=?, duration_seconds=?, error=? WHERE id=?", (now_iso(), round(time.monotonic() - started, 2), str(exc), scan_id))


def latest_scan_ids(conn: sqlite3.Connection, segment_id: str, older: str | None, newer: str | None) -> tuple[str, str]:
    if older and newer:
        return older, newer
    rows = conn.execute("SELECT id FROM scans WHERE segment_id=? AND status='success' ORDER BY started_at DESC LIMIT 2", (segment_id,)).fetchall()
    if len(rows) < 2:
        raise HTTPException(status_code=404, detail="Для сравнения нужны два успешных скана")
    return rows[1]["id"], rows[0]["id"]


def snapshot(conn: sqlite3.Connection, scan_id: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    rows = conn.execute(
        """SELECT h.address, h.hostname, p.id AS port_id, p.port, p.protocol, p.state, p.service, p.product, p.version, p.banner
           FROM hosts h LEFT JOIN ports p ON p.host_id=h.id WHERE h.scan_id=?""",
        (scan_id,),
    ).fetchall()
    for row in rows:
        host = result.setdefault(row["address"], {"hostname": row["hostname"], "ports": {}})
        if row["port"] is not None:
            scripts = conn.execute("SELECT script_id, output FROM scripts WHERE port_id=? ORDER BY script_id", (row["port_id"],)).fetchall()
            host["ports"][(row["port"], row["protocol"])] = {**dict(row), "scripts": [dict(script) for script in scripts]}
    return result


def calculate_changes(conn: sqlite3.Connection, older_id: str, newer_id: str) -> list[dict[str, Any]]:
    older, newer = snapshot(conn, older_id), snapshot(conn, newer_id)
    hosts: list[dict[str, Any]] = []
    for address in sorted(set(older) | set(newer)):
        before, after = older.get(address), newer.get(address)
        changes: list[dict[str, Any]] = []
        if before is None:
            changes.append({"kind": "added", "port": "—", "title": "Обнаружен новый узел", "after": after["hostname"] or address})
        elif after is None:
            changes.append({"kind": "removed", "port": "—", "title": "Узел больше не отвечает", "before": before["hostname"] or address})
        else:
            if before["hostname"] != after["hostname"]:
                changes.append({"kind": "changed", "port": "—", "title": "Изменилось имя узла", "before": before["hostname"], "after": after["hostname"]})
            for key in sorted(set(before["ports"]) | set(after["ports"])):
                left, right = before["ports"].get(key), after["ports"].get(key)
                port_label = f"{key[0]}/{key[1]}"
                if left is None:
                    changes.append({"kind": "added", "port": port_label, "title": "Открыт новый порт", "after": " · ".join(filter(None, (right["service"], right["product"], right["version"])))})
                elif right is None:
                    changes.append({"kind": "removed", "port": port_label, "title": "Порт больше не отвечает", "before": " · ".join(filter(None, (left["service"], left["product"], left["version"])))})
                else:
                    left_value = (left["state"], left["service"], left["product"], left["version"], left["scripts"])
                    right_value = (right["state"], right["service"], right["product"], right["version"], right["scripts"])
                    if left_value != right_value:
                        changes.append({"kind": "changed", "port": port_label, "title": "Изменились данные сервиса или NSE", "before": " · ".join(filter(None, (left["service"], left["product"], left["version"]))), "after": " · ".join(filter(None, (right["service"], right["product"], right["version"])))})
        if changes:
            kinds = {change["kind"] for change in changes}
            hosts.append({"ip": address, "hostname": (after or before)["hostname"], "severity": "high" if "added" in kinds else "medium" if "changed" in kinds else "low", "changes": changes})
    return hosts


@app.get("/api/health")
def health() -> dict[str, Any]:
    scan_files_bytes = sum(path.stat().st_size for path in SCANS_DIR.glob("*.xml") if path.is_file())
    return {
        "status": "ok",
        "nmap": subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=5, check=False).stdout.splitlines()[0] if shutil_which("nmap") else "not installed",
        "database_bytes": DB_PATH.stat().st_size if DB_PATH.exists() else 0,
        "scan_files_bytes": scan_files_bytes,
        "scheduler": "running",
    }


def shutil_which(command: str) -> str | None:
    from shutil import which
    return which(command)


@app.get("/api/dashboard")
def dashboard() -> dict[str, Any]:
    with db() as conn:
        totals = conn.execute("SELECT COUNT(*) AS scans, COALESCE(AVG(duration_seconds),0) AS average_duration FROM scans WHERE status='success'").fetchone()
        hosts = conn.execute("SELECT COUNT(DISTINCT h.address) AS count FROM hosts h JOIN scans s ON s.id=h.scan_id WHERE s.status='success'").fetchone()["count"]
        latest = conn.execute("SELECT * FROM scans ORDER BY started_at DESC LIMIT 1").fetchone()
        return {"scans": totals["scans"], "average_duration": totals["average_duration"], "hosts": hosts, "latest": dict(latest) if latest else None, "settings": load_settings(conn)}


@app.get("/api/segments")
def list_segments() -> list[dict[str, Any]]:
    with db() as conn:
        return [{"id": row["id"], "name": row["name"], "cidrs": row["targets"], "enabled": bool(row["enabled"]), "lastScan": row["last_scan_at"] or "ещё не запускался"} for row in conn.execute("SELECT * FROM segments ORDER BY name")]


@app.get("/api/settings")
def get_settings() -> dict[str, Any]:
    with db() as conn:
        return {**load_settings(conn), "segments": list_segments()}


def validate_settings_payload(payload: SettingsPayload) -> dict[str, Any]:
    values = payload.model_dump(exclude={"segments"})
    if values["speed"] not in {"T1", "T2", "T3", "T4", "T5"}:
        raise HTTPException(status_code=422, detail="speed должен быть от T1 до T5")
    if values["day"] not in {"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday", "daily"}:
        raise HTTPException(status_code=422, detail="Некорректный день расписания")
    try:
        datetime.strptime(values["time"], "%H:%M")
        build_nmap_command("127.0.0.1", Path("/tmp/vizor-check.xml"), values)
        for segment in payload.segments or []:
            normalize_targets(segment.cidrs)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return values


@app.post("/api/settings/validate")
def validate_settings(payload: SettingsPayload) -> dict[str, str]:
    validate_settings_payload(payload)
    return {"status": "valid"}


@app.put("/api/settings")
def update_settings(payload: SettingsPayload) -> dict[str, str]:
    values = validate_settings_payload(payload)
    with db() as conn:
        conn.executemany("INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [(key, json.dumps(value, ensure_ascii=False)) for key, value in values.items()])
        if payload.segments is not None:
            for segment in payload.segments:
                conn.execute("INSERT INTO segments(id, name, targets, enabled) VALUES (?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET name=excluded.name, targets=excluded.targets, enabled=excluded.enabled", (segment.id, segment.name, segment.cidrs, int(segment.enabled)))
    return {"status": "saved"}


@app.get("/api/scans")
def list_scans(segment_id: str | None = None, limit: int = Query(50, ge=1, le=500)) -> list[dict[str, Any]]:
    with db() as conn:
        query = """SELECT s.*, COUNT(DISTINCT h.id) AS hosts, COUNT(p.id) AS ports
                   FROM scans s LEFT JOIN hosts h ON h.scan_id=s.id LEFT JOIN ports p ON p.host_id=h.id"""
        params: list[Any] = []
        if segment_id:
            query += " WHERE s.segment_id=?"
            params.append(segment_id)
        query += " GROUP BY s.id ORDER BY s.started_at DESC LIMIT ?"
        params.append(limit)
        return [dict(row) for row in conn.execute(query, params)]


@app.post("/api/scans/run", status_code=202)
def run_scan(payload: ScanRequest, background_tasks: BackgroundTasks) -> dict[str, str]:
    if not shutil_which("nmap"):
        raise HTTPException(status_code=503, detail="Nmap не установлен")
    scan_id = f"scan-{uuid.uuid4().hex[:12]}"
    with db() as conn:
        segment = conn.execute("SELECT id FROM segments WHERE id=? AND enabled=1", (payload.segment_id,)).fetchone()
        if not segment:
            raise HTTPException(status_code=404, detail="Сегмент не найден или отключён")
        running = conn.execute("SELECT id FROM scans WHERE segment_id=? AND status='running'", (payload.segment_id,)).fetchone()
        if running:
            raise HTTPException(status_code=409, detail="Сканирование сегмента уже выполняется")
        conn.execute("INSERT INTO scans(id, segment_id, started_at, status) VALUES (?, ?, ?, 'running')", (scan_id, payload.segment_id, now_iso()))
    background_tasks.add_task(execute_scan, scan_id, payload.segment_id)
    return {"id": scan_id, "status": "running"}


@app.post("/api/import", status_code=201)
async def import_xml(file: UploadFile = File(...), segment_id: str = "manual") -> dict[str, Any]:
    content = await file.read(MAX_XML_BYTES + 1)
    if len(content) > MAX_XML_BYTES:
        raise HTTPException(status_code=413, detail="XML превышает 100 МБ")
    scan_id = f"import-{uuid.uuid4().hex[:12]}"
    xml_path = SCANS_DIR / f"{scan_id}.xml"
    xml_path.write_bytes(content)
    with db() as conn:
        conn.execute("INSERT OR IGNORE INTO segments(id, name, targets, enabled) VALUES (?, 'Ручной импорт', 'manual', 1)", (segment_id,))
        conn.execute("INSERT INTO scans(id, segment_id, started_at, finished_at, status, xml_path) VALUES (?, ?, ?, ?, 'success', ?)", (scan_id, segment_id, now_iso(), now_iso(), str(xml_path)))
    try:
        counts = parse_xml_into_db(scan_id, xml_path)
    except ValueError as exc:
        with db() as conn:
            conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        xml_path.unlink(missing_ok=True)
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"id": scan_id, **counts}


@app.get("/api/search")
def search_inventory(segment_id: str | None = None, q: str = "", port: int | None = None, service: str = "", script: str = "", limit: int = Query(500, ge=1, le=5000)) -> list[dict[str, Any]]:
    with db() as conn:
        clauses = ["s.status='success'", "s.id=(SELECT s2.id FROM scans s2 WHERE s2.segment_id=s.segment_id AND s2.status='success' ORDER BY s2.started_at DESC LIMIT 1)"]
        params: list[Any] = []
        if segment_id:
            clauses.append("s.segment_id=?"); params.append(segment_id)
        if port is not None:
            clauses.append("p.port=?"); params.append(port)
        if service:
            clauses.append("LOWER(COALESCE(p.service,'') || ' ' || COALESCE(p.product,'')) LIKE ?"); params.append(f"%{service.lower()}%")
        if q:
            clauses.append("LOWER(h.address || ' ' || COALESCE(h.hostname,'') || ' ' || COALESCE(p.service,'') || ' ' || COALESCE(p.product,'') || ' ' || COALESCE(p.version,'') || ' ' || COALESCE(p.banner,'')) LIKE ?"); params.append(f"%{q.lower()}%")
        if script:
            clauses.append("EXISTS (SELECT 1 FROM scripts sx WHERE sx.host_id=h.id AND (sx.port_id=p.id OR sx.port_id IS NULL) AND LOWER(sx.script_id || ' ' || COALESCE(sx.output,'')) LIKE ?)"); params.append(f"%{script.lower()}%")
        query = f"""SELECT s.segment_id, h.address AS ip, h.hostname, p.id AS port_id, p.port, p.protocol, p.state, p.service, p.product, p.version, p.banner
                    FROM scans s JOIN hosts h ON h.scan_id=s.id JOIN ports p ON p.host_id=h.id
                    WHERE {' AND '.join(clauses)} ORDER BY h.address, p.port LIMIT ?"""
        params.append(limit)
        result = []
        for row in conn.execute(query, params):
            scripts = [dict(item) for item in conn.execute("SELECT script_id AS id, output FROM scripts WHERE host_id=(SELECT host_id FROM ports WHERE id=?) AND (port_id=? OR port_id IS NULL) ORDER BY script_id", (row["port_id"], row["port_id"]))]
            item = dict(row); item.pop("port_id"); item["scripts"] = scripts; result.append(item)
        return result


@app.get("/api/changes")
def changes(segment_id: str, older: str | None = None, newer: str | None = None) -> dict[str, Any]:
    with db() as conn:
        older_id, newer_id = latest_scan_ids(conn, segment_id, older, newer)
        return {"older": older_id, "newer": newer_id, "hosts": calculate_changes(conn, older_id, newer_id)}


@app.get("/api/reports/changes.pdf")
def changes_pdf(segment_id: str, older: str | None = None, newer: str | None = None) -> Response:
    with db() as conn:
        older_id, newer_id = latest_scan_ids(conn, segment_id, older, newer)
        items = calculate_changes(conn, older_id, newer_id)
        segment = conn.execute("SELECT name FROM segments WHERE id=?", (segment_id,)).fetchone()
    buffer = io.BytesIO()
    font_name = "Helvetica"
    for font_path in ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf"):
        if Path(font_path).exists():
            pdfmetrics.registerFont(TTFont("VizorSans", font_path)); font_name = "VizorSans"; break
    document = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=16*mm, rightMargin=16*mm, topMargin=15*mm, bottomMargin=15*mm)
    styles = getSampleStyleSheet(); styles["Title"].fontName = font_name; styles["BodyText"].fontName = font_name
    story: list[Any] = [Paragraph(f"Vizor — изменения: {segment['name'] if segment else segment_id}", styles["Title"]), Paragraph(f"Сравнение {older_id} → {newer_id}. Создано {datetime.now().strftime('%d.%m.%Y %H:%M')}", styles["BodyText"]), Spacer(1, 7*mm)]
    rows = [["Узел", "Порт", "Тип", "Изменение"]]
    for host in items:
        for change in host["changes"]:
            rows.append([f"{host['hostname']}\n{host['ip']}", change["port"], change["kind"], f"{change['title']}\n{change.get('before','')} → {change.get('after','')}"])
    table = Table(rows, colWidths=[38*mm, 24*mm, 22*mm, 95*mm], repeatRows=1)
    table.setStyle(TableStyle([("FONTNAME", (0,0), (-1,-1), font_name), ("FONTSIZE", (0,0), (-1,-1), 7.5), ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#20242a")), ("TEXTCOLOR", (0,0), (-1,0), colors.white), ("GRID", (0,0), (-1,-1), .3, colors.HexColor("#9aa0a6")), ("VALIGN", (0,0), (-1,-1), "TOP"), ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f4f5f6")]), ("LEFTPADDING", (0,0), (-1,-1), 5), ("RIGHTPADDING", (0,0), (-1,-1), 5)]))
    story.append(table); document.build(story)
    return Response(buffer.getvalue(), media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="vizor-{segment_id}-changes.pdf"'})


def scheduler_loop() -> None:
    last_key = ""
    weekdays = {"monday": 0, "tuesday": 1, "wednesday": 2, "thursday": 3, "friday": 4, "saturday": 5, "sunday": 6}
    while True:
        try:
            current = datetime.now()
            settings = load_settings()
            expected_day = settings.get("day", "monday")
            expected_time = settings.get("time", "11:00")
            due_day = expected_day == "daily" or weekdays.get(expected_day) == current.weekday()
            key = current.strftime("%Y-%m-%d %H:%M")
            if settings.get("schedule_enabled", True) and due_day and current.strftime("%H:%M") == expected_time and key != last_key:
                with db() as conn:
                    segment_ids = [row["id"] for row in conn.execute("SELECT id FROM segments WHERE enabled=1 AND id!='manual'")]
                    for segment_id in segment_ids:
                        scan_id = f"scan-{uuid.uuid4().hex[:12]}"
                        conn.execute("INSERT INTO scans(id, segment_id, started_at, status) VALUES (?, ?, ?, 'running')", (scan_id, segment_id, now_iso()))
                        threading.Thread(target=execute_scan, args=(scan_id, segment_id), daemon=True).start()
                last_key = key
        except Exception:
            pass
        time.sleep(30)
