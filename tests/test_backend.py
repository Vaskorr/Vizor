import importlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient


SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up" />
    <address addr="10.20.1.17" addrtype="ipv4" />
    <hostnames><hostname name="gw-core-01" /></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" />
        <service name="https" product="nginx" version="1.24.0" />
        <script id="ssl-cert" output="CN=gw-core.intra" />
      </port>
    </ports>
  </host>
</nmaprun>
"""


class VizorBackendTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ["VIZOR_DATA_DIR"] = self.temp_dir.name
        os.environ["VIZOR_USERNAME"] = "vizor"
        os.environ["VIZOR_PASSWORD"] = "vizor"
        os.environ["VIZOR_COOKIE_SECURE"] = "false"
        import server.main
        self.main = importlib.reload(server.main)
        self.main.init_db()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_command_is_argument_safe(self):
        command = self.main.build_nmap_command(
            "10.20.0.0/24, 10.20.8.0/24",
            Path(self.temp_dir.name) / "scan.xml",
            {"speed": "T3", "flags": "-sV --reason", "scripts": "default,safe", "exclusions": "10.20.0.1"},
        )
        self.assertEqual(command[0:4], ["nmap", "-T3", "-sV", "--reason"])
        self.assertIn("10.20.0.0/24", command)
        self.assertNotIn("shell=True", command)

    def test_authentication_protects_api_and_uses_generic_login_error(self):
        with TestClient(self.main.app) as client:
            self.assertEqual(client.get("/api/health").status_code, 200)
            protected = client.get("/api/settings", headers={"Origin": "http://localhost:3000"})
            self.assertEqual(protected.status_code, 401)
            self.assertEqual(protected.headers["access-control-allow-origin"], "http://localhost:3000")
            self.assertEqual(protected.headers["access-control-allow-credentials"], "true")
            self.assertEqual(client.get("/docs").status_code, 401)

            for username, password in (("wrong", "vizor"), ("vizor", "wrong"), ("", "")):
                response = client.post("/api/auth/login", json={"username": username, "password": password})
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.json(), {"detail": "Неверный логин или пароль"})

            login = client.post(
                "/api/auth/login",
                json={"username": "vizor", "password": "vizor"},
                headers={"Origin": "http://localhost:3000"},
            )
            self.assertEqual(login.status_code, 200)
            self.assertEqual(login.headers["access-control-allow-origin"], "http://localhost:3000")
            cookie = login.headers["set-cookie"]
            self.assertIn("HttpOnly", cookie)
            self.assertIn("SameSite=strict", cookie)
            self.assertEqual(client.get("/api/settings").status_code, 200)
            self.assertEqual(client.get("/api/auth/session").status_code, 200)

            self.assertEqual(client.post("/api/auth/logout").status_code, 200)
            self.assertEqual(client.get("/api/settings").status_code, 401)

    def test_rejects_shell_and_argument_injection(self):
        base = {"speed": "T3", "flags": "-sV --reason", "scripts": "default,safe", "exclusions": ""}
        malicious_flags = [
            "-sV; touch /tmp/pwned",
            "-sV $(id)",
            "-sV `id`",
            "-sV && id",
            "-sV 192.168.0.0/16",
            "-sV -- 192.168.0.0/16",
            "--datadir /tmp",
            "--datadir=/tmp",
            "-oX /tmp/stolen.xml",
            "-oX/tmp/stolen.xml",
            "--script /tmp/evil.nse",
            "--script=../evil",
            "--script-args-file /etc/passwd",
            "-iL /etc/passwd",
            "-iR100",
            "--excludefile=/etc/passwd",
            "--resume /tmp/scan.nmap",
        ]
        for flags in malicious_flags:
            with self.subTest(flags=flags), self.assertRaises(ValueError):
                self.main.build_nmap_command("127.0.0.1", Path(self.temp_dir.name) / "scan.xml", {**base, "flags": flags})

        with self.assertRaises(ValueError):
            self.main.build_nmap_command("127.0.0.1;id", Path(self.temp_dir.name) / "scan.xml", base)
        with self.assertRaises(ValueError):
            self.main.build_nmap_command("127.0.0.1", Path(self.temp_dir.name) / "scan.xml", {**base, "scripts": "../../evil.nse"})

    def test_accepts_full_scan_option_grammar(self):
        flags = self.main.parse_safe_nmap_flags("-sS -sV -Pn -p 22,80,443 --top-ports 100 --host-timeout 5m")
        self.assertEqual(flags, ["-sS", "-sV", "-Pn", "-p", "22,80,443", "--top-ports", "100", "--host-timeout", "5m"])

        comprehensive = self.main.parse_safe_nmap_flags(
            "-sn -PS80,443 -PA -PU53 -PY80 -PO1,6 --dns-servers 10.0.0.53 "
            "--system-dns --traceroute -sT -sU --scanflags SYN,ACK "
            "-pT:22,80,U:53 --exclude-ports 25 --top-ports=100 --port-ratio 0.1 "
            "-sV --version-intensity 7 --version-trace -sC "
            "--script 'default and not intrusive' "
            "--script-args 'http.useragent=Vizor Test,token=$(id);literal=true' "
            "--script-timeout 30s -O --osscan-guess --max-os-tries 3 -T4 "
            "--min-hostgroup 16 --max-parallelism 50 --min-rtt-timeout 100ms "
            "--max-rtt-timeout 2s --max-retries 10 --host-timeout 5m "
            "--scan-delay 10ms --max-scan-delay 1s --min-rate 10.5 --max-rate 1000 "
            "--stats-every 15s -ff --mtu 24 -D RND:5,ME -S 10.0.0.1 -e eth0 "
            "-g53 --proxies http://proxy.internal:8080 --data deadbeef "
            "--data-string 'hello;$(id)' --data-length 16 --ip-options R --ttl 64 "
            "--spoof-mac 0 -vv -d2 --reason --open --packet-trace --noninteractive "
            "--stylesheet https://nmap.org/svn/docs/nmap.xsl --webxml -6 -A --send-ip --privileged"
        )
        self.assertIn("--script-args", comprehensive)
        self.assertIn("http.useragent=Vizor Test,token=$(id);literal=true", comprehensive)
        self.assertIn("hello;$(id)", comprehensive)
        self.assertIn("-g", comprehensive)
        self.assertIn("53", comprehensive)

    def test_accepts_inline_values_and_safe_exclusions(self):
        flags = self.main.parse_safe_nmap_flags(
            "-p443 -sIzombie.internal:80 -Ddecoy.internal,ME -S10.0.0.10 -eeth0 "
            "--source-port=53 --exclude=10.0.0.1,10.0.2.0/24 --script=http-*"
        )
        self.assertEqual(flags[0:2], ["-p", "443"])
        self.assertIn("--exclude", flags)
        self.assertIn("10.0.0.1,10.0.2.0/24", flags)
        self.assertEqual(flags[-2:], ["--script", "http-*"])

    def test_rejects_unknown_missing_and_invalid_option_values(self):
        invalid = [
            "--definitely-not-an-nmap-option",
            "-p",
            "-p 80;id",
            "--version-intensity 10",
            "--port-ratio 1.1",
            "--mtu 23",
            "--data xyz",
            "--exclude example.org",
            "--script ../../evil.nse",
            "--host-timeout forever",
            "-T9",
        ]
        for flags in invalid:
            with self.subTest(flags=flags), self.assertRaises(ValueError):
                self.main.parse_safe_nmap_flags(flags)

    def test_settings_validation_uses_the_same_backend_parser(self):
        payload = self.main.SettingsPayload(
            flags="-sV -pT:22,443,U:53 --script 'default or safe' --script-args 'k=$(id);x=1'",
            scripts="default and safe",
        )
        values = self.main.validate_settings_payload(payload)
        self.assertEqual(values["flags"], payload.flags)

        with self.assertRaises(self.main.HTTPException) as context:
            self.main.validate_settings_payload(self.main.SettingsPayload(flags="-sV; id"))
        self.assertEqual(context.exception.status_code, 422)

    def test_scan_process_receives_argv_without_a_shell(self):
        literal_payload = "$(touch /tmp/vizor-rce-marker);`id`"
        with self.main.db() as connection:
            connection.execute(
                "INSERT INTO segments(id, name, targets, enabled) VALUES ('local', 'Local', '127.0.0.1', 1)"
            )
            connection.execute(
                "INSERT INTO scans(id, segment_id, started_at, status) VALUES ('scan-safe', 'local', ?, 'running')",
                (self.main.now_iso(),),
            )
            connection.execute(
                "INSERT INTO settings(key, value) VALUES ('flags', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (json.dumps(f"-sn --data-string '{literal_payload}'"),),
            )
            connection.execute(
                "INSERT INTO settings(key, value) VALUES ('scripts', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (json.dumps(""),),
            )

        def fake_run(command, **kwargs):
            self.assertIsInstance(command, list)
            self.assertIs(kwargs["shell"], False)
            self.assertIn(literal_payload, command)
            output_path = Path(command[command.index("-oX") + 1])
            output_path.write_text(SAMPLE_XML, encoding="utf-8")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch.object(self.main.subprocess, "run", side_effect=fake_run):
            self.main.execute_scan("scan-safe", "local")

        with self.main.db() as connection:
            status = connection.execute("SELECT status FROM scans WHERE id='scan-safe'").fetchone()["status"]
        self.assertEqual(status, "success")

    def test_parse_xml_and_searchable_schema(self):
        xml_path = Path(self.temp_dir.name) / "sample.xml"
        xml_path.write_text(SAMPLE_XML, encoding="utf-8")
        with self.main.db() as connection:
            connection.execute(
                "INSERT INTO segments(id, name, targets, enabled) VALUES ('corp', 'Test segment', '127.0.0.1', 1)"
            )
            connection.execute(
                "INSERT INTO scans(id, segment_id, started_at, status) VALUES ('test-scan', 'corp', ?, 'success')",
                (self.main.now_iso(),),
            )
        counts = self.main.parse_xml_into_db("test-scan", xml_path)
        self.assertEqual(counts, {"hosts": 1, "ports": 1, "scripts": 1})
        with self.main.db() as connection:
            row = connection.execute(
                "SELECT h.address, p.port, p.product FROM hosts h JOIN ports p ON p.host_id=h.id"
            ).fetchone()
            script = connection.execute("SELECT script_id, output FROM scripts").fetchone()
        self.assertEqual((row["address"], row["port"], row["product"]), ("10.20.1.17", 443, "nginx"))
        self.assertEqual(script["script_id"], "ssl-cert")

    def test_production_database_has_no_seed_segments(self):
        with self.main.db() as connection:
            count = connection.execute("SELECT COUNT(*) FROM segments").fetchone()[0]
        self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
