import importlib
import os
import tempfile
import unittest
from pathlib import Path


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

    def test_rejects_shell_and_argument_injection(self):
        base = {"speed": "T3", "flags": "-sV --reason", "scripts": "default,safe", "exclusions": ""}
        malicious_flags = [
            "-sV; touch /tmp/pwned",
            "-sV $(id)",
            "-sV `id`",
            "--datadir /tmp",
            "-oX /tmp/stolen.xml",
            "--script /tmp/evil.nse",
            "-iL /etc/passwd",
        ]
        for flags in malicious_flags:
            with self.subTest(flags=flags), self.assertRaises(ValueError):
                self.main.build_nmap_command("127.0.0.1", Path(self.temp_dir.name) / "scan.xml", {**base, "flags": flags})

        with self.assertRaises(ValueError):
            self.main.build_nmap_command("127.0.0.1;id", Path(self.temp_dir.name) / "scan.xml", base)
        with self.assertRaises(ValueError):
            self.main.build_nmap_command("127.0.0.1", Path(self.temp_dir.name) / "scan.xml", {**base, "scripts": "../../evil.nse"})

    def test_accepts_allowlisted_flags_only(self):
        flags = self.main.parse_safe_nmap_flags("-sS -sV -Pn -p 22,80,443 --top-ports 100 --host-timeout 5m")
        self.assertEqual(flags, ["-sS", "-sV", "-Pn", "-p", "22,80,443", "--top-ports", "100", "--host-timeout", "5m"])

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
