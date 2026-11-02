import importlib.machinery
import importlib.util
import io
import json
import os
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).with_name("rift-site")
loader = importlib.machinery.SourceFileLoader("rift_site", str(SCRIPT))
spec = importlib.util.spec_from_loader("rift_site", loader)
rift_site = importlib.util.module_from_spec(spec)
loader.exec_module(rift_site)


class RenderTests(unittest.TestCase):
    def test_traefik_matches_the_two_router_pattern(self):
        text = rift_site.render_traefik(
            "app.makl.xyz", "http://181.214.231.165:20000", "myresolver", "web", "websecure"
        )
        self.assertIn("rule: Host(`app.makl.xyz`)", text)
        self.assertIn("certResolver: myresolver", text)
        self.assertIn("- web\n", text)
        self.assertIn("- websecure\n", text)
        self.assertIn("url: http://181.214.231.165:20000", text)

    def test_caddy_and_nginx_point_at_the_public_forward(self):
        self.assertEqual(
            rift_site.render_caddy("app.makl.xyz", "http://181.214.231.165:20000"),
            "app.makl.xyz {\n    reverse_proxy 181.214.231.165:20000\n}\n",
        )
        nginx = rift_site.render_nginx("app.makl.xyz", "http://181.214.231.165:20000")
        self.assertIn("server_name app.makl.xyz;", nginx)
        self.assertIn("proxy_pass http://181.214.231.165:20000;", nginx)

    def test_public_ip_comes_from_env_before_toml(self):
        toml = 'public_ips = ["203.0.113.10"]\n'
        self.assertEqual(rift_site.resolve_public_ip(toml, "198.51.100.10"), "198.51.100.10")
        self.assertEqual(rift_site.resolve_public_ip(toml, ""), "203.0.113.10")
        self.assertEqual(rift_site.resolve_public_ip("", " 198.51.100.10 "), "198.51.100.10")
        # Dual stack: the first IPv4 address, wherever it is listed.
        self.assertEqual(
            rift_site.resolve_public_ip("", "2001:db8::1, 198.51.100.10"), "198.51.100.10"
        )
        self.assertEqual(rift_site.resolve_public_ip("", "2001:db8::1"), "2001:db8::1")
        with self.assertRaises(rift_site.SiteError):
            rift_site.resolve_public_ip("", "")
        with self.assertRaises(rift_site.SiteError):
            rift_site.resolve_public_ip("", "rift.example.net")
        with self.assertRaises(rift_site.SiteError):
            rift_site.resolve_public_ip("", "2001:db8::1,rift.example.net")

    def test_missing_agent_says_enrollment_is_unfinished(self):
        self.assertIn(
            "has not finished enrollment",
            rift_site.missing_agent_message("core", "rift: agent not found"),
        )
        self.assertEqual(
            rift_site.missing_agent_message("core", "connection refused"),
            "connection refused",
        )

    def test_allocate_reuses_the_first_free_port(self):
        self.assertEqual(rift_site.allocate_port({20000, 20001}, 20000, 20999), 20002)
        with self.assertRaises(rift_site.SiteError):
            rift_site.allocate_port(set(range(20000, 20002)), 20000, 20001)


class EdgeTests(unittest.TestCase):
    def setUp(self):
        self.traefik = [
            {
                "name": "traefik",
                "image": "traefik:latest",
                "ports": "0.0.0.0:443->443/tcp, :::443->443/tcp",
            },
            {
                "name": "fluxer-edge-1",
                "image": "caddy:2.10-alpine",
                "ports": "127.0.0.1:8081->80/tcp",
            },
        ]

    def test_traefik_is_the_edge_when_it_publishes_443(self):
        rift_site.require_edge("traefik", self.traefik, ["docker-proxy"])

    def test_caddy_and_nginx_are_refused_while_traefik_holds_443(self):
        for proxy in ("caddy", "nginx"):
            with self.assertRaises(rift_site.SiteError) as caught:
                rift_site.require_edge(proxy, self.traefik, ["docker-proxy"])
            self.assertIn("traefik holds port 443", str(caught.exception))

    def test_ss_ignores_unrelated_ports(self):
        text = '\n'.join(
            [
                'LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("docker-proxy",pid=1,fd=4))',
                'LISTEN 0 128 0.0.0.0:2269 0.0.0.0:* users:(("sshd",pid=2,fd=3))',
                'LISTEN 0 4096 [::]:443 [::]:* users:(("docker-proxy",pid=1,fd=5))',
            ]
        )
        self.assertEqual(rift_site.listeners_from_ss(text), ["docker-proxy", "docker-proxy"])


class NpmTests(unittest.TestCase):
    def test_nginx_proxy_manager_is_not_mistaken_for_plain_nginx(self):
        npm = [
            {
                "name": "nginx-proxy-manager-app-1",
                "image": "jc21/nginx-proxy-manager:latest",
                "ports": "0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp, 0.0.0.0:81->81/tcp",
            }
        ]
        self.assertEqual(rift_site.edge_holders(npm, ["docker-proxy"]), ["npm"])
        rift_site.require_edge("npm", npm, ["docker-proxy"])
        with self.assertRaises(rift_site.SiteError):
            rift_site.require_edge("nginx", npm, ["docker-proxy"])
        self.assertEqual(rift_site.proxy_kind("npm", "jc21/nginx-proxy-manager"), "npm")
        self.assertEqual(rift_site.proxy_kind("web", "nginx:alpine"), "nginx")

    def test_proxy_host_points_at_the_local_forward(self):
        payload = rift_site.npm_host_payload("app.example.net", "203.0.113.10", 20000, 0)
        self.assertEqual(payload["domain_names"], ["app.example.net"])
        self.assertEqual(payload["forward_host"], "203.0.113.10")
        self.assertEqual(payload["forward_port"], 20000)
        self.assertFalse(payload["ssl_forced"])
        secured = rift_site.npm_host_payload("app.example.net", "203.0.113.10", 20000, 7)
        self.assertEqual(secured["certificate_id"], 7)
        self.assertTrue(secured["ssl_forced"])

    def remove_with(self, certificate_domains, other_users):
        calls = []

        def fake(settings, method, path, body=None, token=None):
            calls.append((method, path))
            if path == "/nginx/certificates/7" and method == "GET":
                return {"domain_names": certificate_domains}
            if path == "/nginx/proxy-hosts":
                return other_users
            if path.startswith("/nginx/") and method == "GET":
                return []
            return None

        original = rift_site.npm_request
        rift_site.npm_request = fake
        try:
            rift_site.npm_remove_certificate({}, "t", 7, "app.example.net")
        finally:
            rift_site.npm_request = original
        return ("DELETE", "/nginx/certificates/7") in calls

    def test_certificate_is_deleted_only_when_exclusive_and_unused(self):
        self.assertTrue(self.remove_with(["app.example.net"], []))
        self.assertFalse(self.remove_with(["*.example.net"], []))
        self.assertFalse(self.remove_with(["app.example.net", "b.example.net"], []))
        self.assertFalse(self.remove_with(["app.example.net"], [{"certificate_id": 7}]))

    def test_certbot_registers_without_email_when_none_is_configured(self):
        self.assertEqual(
            rift_site.certbot_command("app.example.net", ""),
            [
                "certbot", "--nginx", "--non-interactive", "--agree-tos",
                "--register-unsafely-without-email", "-d", "app.example.net",
            ],
        )
        self.assertEqual(
            rift_site.certbot_command("app.example.net", "a@example.net")[4:],
            ["--email", "a@example.net", "-d", "app.example.net"],
        )

    def test_certificate_request_flag(self):
        original = rift_site.site_setting
        try:
            for value, expected in [("", True), ("true", True), ("false", False), ("No", False), ("0", False)]:
                rift_site.site_setting = lambda key, container="rift-server", v=value: v
                self.assertEqual(rift_site.request_certificate(), expected, value)
        finally:
            rift_site.site_setting = original

    def test_env_file_parsing(self):
        values = rift_site.parse_env_file(
            '# c\nRIFT_NPM_EMAIL="a@example.net"\nRIFT_NPM_PASSWORD=pw=1\n\nbad\n'
        )
        self.assertEqual(values, {"RIFT_NPM_EMAIL": "a@example.net", "RIFT_NPM_PASSWORD": "pw=1"})


LABEL_ONLY_COMPOSE = """services:
  traefik:
    image: traefik:v3
    container_name: traefik
    command:
      - "--providers.docker=true"
      # comment between items
      - "--certificatesresolvers.myresolver.acme.email=${ACME_EMAIL}" # via .env
      - "--log.level=DEBUG"
    ports:
      - "80:80"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./traefik/acme.json:/acme.json
    restart: unless-stopped

  docker-proxy:
    image: tecnativa/docker-socket-proxy
    command:
      - "--other"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
"""


class FileProviderTests(unittest.TestCase):
    def test_label_only_traefik_gets_a_watched_file_provider(self):
        text, changed = rift_site.add_file_provider(
            LABEL_ONLY_COMPOSE, "traefik", "/home/ubuntu/service/dynamic"
        )
        self.assertTrue(changed)
        self.assertIn(
            '      - "--log.level=DEBUG"\n'
            '      - "--providers.file.directory=/dynamic"\n'
            '      - "--providers.file.watch=true"\n',
            text,
        )
        self.assertIn(
            "      - ./traefik/acme.json:/acme.json\n"
            "      - /home/ubuntu/service/dynamic:/dynamic:ro\n",
            text,
        )
        self.assertIn("${ACME_EMAIL}", text)
        # The neighbouring service stays untouched.
        self.assertEqual(text.count("/dynamic"), 3)
        self.assertEqual(text.split("docker-proxy:")[1], LABEL_ONLY_COMPOSE.split("docker-proxy:")[1])

    def test_unknown_service_or_missing_lists_change_nothing(self):
        self.assertEqual(rift_site.add_file_provider(LABEL_ONLY_COMPOSE, "nope", "/d"), (LABEL_ONLY_COMPOSE, False))
        no_volumes = "services:\n  traefik:\n    command:\n      - \"--x\"\n"
        self.assertEqual(rift_site.add_file_provider(no_volumes, "traefik", "/d"), (no_volumes, False))

    def test_backup_notice_says_when_it_is_safe_to_delete(self):
        compose, backup = Path("/srv/docker-compose.yml"), Path("/srv/docker-compose.yml.rift-bak")
        fresh = rift_site.backup_notice(compose, backup, True)
        self.assertIn(str(backup), fresh)
        self.assertIn("safe to delete", fresh)
        self.assertNotIn("safe to delete", rift_site.backup_notice(compose, backup, False))

    def test_dns_hint_prefers_the_public_endpoint_over_the_bind_address(self):
        state = {"container": "rift-server", "public_ip": "10.0.0.45"}
        original_setting, original_lookup = rift_site.site_setting, rift_site.socket.getaddrinfo
        try:
            rift_site.site_setting = lambda key, container="rift-server": "rift.example.net"
            rift_site.socket.getaddrinfo = lambda *a, **k: [(2, 1, 6, "", ("161.118.177.113", 0))]
            self.assertEqual(
                rift_site.dns_hint("app.example.net", state),
                "DNS: app.example.net -> 161.118.177.113 (address of rift.example.net)",
            )
            rift_site.site_setting = lambda key, container="rift-server": "203.0.113.5"
            self.assertIn("203.0.113.5", rift_site.dns_hint("app.example.net", state))

            def fail(*a, **k):
                raise OSError("no dns")

            rift_site.site_setting = lambda key, container="rift-server": "rift.example.net"
            rift_site.socket.getaddrinfo = fail
            self.assertEqual(rift_site.dns_hint("app.example.net", state), "DNS: app.example.net -> 10.0.0.45")
            rift_site.site_setting = lambda key, container="rift-server": ""
            self.assertEqual(rift_site.dns_hint("app.example.net", state), "DNS: app.example.net -> 10.0.0.45")
        finally:
            rift_site.site_setting, rift_site.socket.getaddrinfo = original_setting, original_lookup

    def test_site_files_go_where_traefik_actually_reads(self):
        inspected = json.dumps(
            [
                {
                    "Args": ["--providers.file.directory=/dynamic", "--providers.file.watch=true"],
                    "Mounts": [{"Source": "/home/ubuntu/service/dynamic", "Destination": "/dynamic"}],
                    "Config": {"Labels": {}},
                }
            ]
        )
        state = {"traefik": {"dynamic_dir": rift_site.DEFAULT_TRAEFIK_DIR}}
        original = rift_site.run
        rift_site.run = lambda cmd, cwd=None: inspected
        try:
            self.assertIsNone(rift_site.ensure_traefik_provider(state))
        finally:
            rift_site.run = original
        self.assertEqual(state["traefik"]["dynamic_dir"], "/home/ubuntu/service/dynamic")

    def test_forward_table_names_the_site_behind_each_forward(self):
        forwards = [
            {"id": 1, "agent_id": "a1", "protocol": "tcp", "listen_ip": "10.0.0.207",
             "listen_ports": {"start": 20000, "end": 20000}, "target_ports": {"start": 8091, "end": 8091},
             "target_family": "v4", "ingress": "local", "mode": "transparent", "enabled": True},
            {"id": 3, "agent_id": "a1", "protocol": "tcp", "listen_ip": "2001:db8::1",
             "listen_ports": {"start": 1337, "end": 1339}, "target_ports": {"start": 1337, "end": 1339},
             "target_family": "v6", "ingress": "public", "mode": "transparent", "enabled": False},
            {"id": 4, "agent_id": "a1", "protocol": "udp", "listen_ip": "10.0.0.207",
             "listen_ports": {"start": 51821, "end": 51821}, "target_ports": {"start": 51821, "end": 51821},
             "target_family": "v4", "ingress": "public", "mode": "transparent", "enabled": True,
             "purpose": "exit", "state": "enabled"},
        ]
        agents = [{"id": "a1", "name": "heim"}]
        sites = {"beszel.example.net": {"forward_id": 1, "proxy": "traefik"}}
        rows = rift_site.forward_rows(forwards, agents, sites)
        self.assertEqual(rows[0][-1], "SITE")
        self.assertEqual(
            rows[1],
            ("1", "heim", "TCP", "10.0.0.207:20000", "8091", "v4", "local", "transparent", "user",
             "enabled", "beszel.example.net (traefik)"),
        )
        self.assertEqual(rows[2][3], "[2001:db8::1]:1337-1339")
        self.assertEqual(rows[2][8:], ("user", "disabled", ""))
        # The managed forward of an internet exit says so.
        self.assertEqual(rows[3][8:], ("exit", "enabled", ""))

    def test_add_arguments_and_the_proxy_word(self):
        self.assertEqual(
            rift_site.parse_add_args(["core", "a.example", "8081", "traefik"]),
            (["core", "a.example", "8081"], "traefik"),
        )
        self.assertEqual(rift_site.parse_add_args(["core", "a.example", "8081"])[1], None)
        with self.assertRaises(rift_site.SiteError) as typo:
            rift_site.parse_add_args(["core", "a.example", "8081", "traefic"])
        self.assertIn("unknown proxy traefic", str(typo.exception))
        for bad in (
            ["core", "a.example", "8081", "--proxy", "traefik"],
            ["core", "a.example"],
            ["a", "b", "1", "npm", "x"],
        ):
            with self.assertRaises(rift_site.SiteError):
                rift_site.parse_add_args(bad)

    def test_a_refused_forward_reports_the_reason(self):
        forwards = [
            {"id": 1, "state": "enabled"},
            {"id": 6, "state": "refused", "refused": "the agent allows only ports 8081; add 8080/tcp"},
        ]
        self.assertIsNone(rift_site.refusal(forwards, 1))
        self.assertIn("add 8080/tcp", rift_site.refusal(forwards, 6))
        self.assertIsNone(rift_site.refusal(forwards, 9))

    def test_messages_name_the_command_not_the_file(self):
        self.assertIn("usage: rift add site", rift_site.usage())
        self.assertNotIn("rift-site", rift_site.usage())

    def test_a_site_forward_removed_by_hand_is_not_trusted(self):
        site = {"forward_id": 2, "listen": 20001, "target": 3001}

        def forward(forward_id, listen, target):
            return {
                "id": forward_id,
                "listen_ports": {"start": listen, "end": listen},
                "target_ports": {"start": target, "end": target},
            }

        mine = forward(2, 20001, 3001)
        self.assertTrue(rift_site.site_forward_alive(site, [forward(1, 20000, 8081), mine]))
        self.assertFalse(rift_site.site_forward_alive(site, [forward(1, 20000, 8081)]))
        self.assertFalse(rift_site.site_forward_alive({}, [mine]))
        # The ID was freed and handed to another forward: same ID, different ports.
        self.assertFalse(rift_site.site_forward_alive(site, [forward(2, 20003, 8080)]))
        self.assertFalse(rift_site.site_forward_alive(site, [forward(2, 20001, 9999)]))

    def test_detects_an_existing_file_provider(self):
        self.assertTrue(rift_site.has_file_provider({"args": ["--providers.file.filename=/x.yml"]}))
        self.assertFalse(rift_site.has_file_provider({"args": ["--providers.docker=true"]}))


class ComposeTests(unittest.TestCase):
    def test_single_file_provider_becomes_a_watched_directory(self):
        original = """services:
  traefik:
    command:
      - "--providers.docker=true"
      - "--providers.file.filename=/dynamic_conf.yml"
    volumes:
      - /root/traefik/acme.json:/acme.json
      - /root/traefik/dynamic_conf.yml:/dynamic_conf.yml:ro
"""
        migrated, changed = rift_site.migrate_compose(original)
        self.assertTrue(changed)
        self.assertNotIn("dynamic_conf.yml", migrated)
        self.assertIn('"--providers.file.directory=/dynamic"', migrated)
        self.assertIn('"--providers.file.watch=true"', migrated)
        self.assertIn("/root/traefik/dynamic:/dynamic:ro", migrated)
        self.assertIn("/root/traefik/acme.json:/acme.json", migrated)
        again, changed_again = rift_site.migrate_compose(migrated)
        self.assertFalse(changed_again)
        self.assertEqual(again, migrated)

    def test_layout_detects_a_ready_directory_provider(self):
        ready = rift_site.traefik_layout(
            [
                {
                    "Args": ["--providers.file.directory=/dynamic", "--providers.file.watch=true"],
                    "Mounts": [{"Source": "/root/traefik/dynamic", "Destination": "/dynamic"}],
                    "Config": {"Labels": {}},
                }
            ]
        )
        self.assertTrue(ready["ready"])
        self.assertEqual(ready["dynamic_source"], "/root/traefik/dynamic")
        pending = rift_site.traefik_layout(
            [
                {
                    "Args": ["--providers.file.filename=/dynamic_conf.yml"],
                    "Mounts": [
                        {
                            "Source": "/root/traefik/dynamic_conf.yml",
                            "Destination": "/dynamic_conf.yml",
                        }
                    ],
                    "Config": {
                        "Labels": {
                            "com.docker.compose.project.working_dir": "/root/traefik",
                            "com.docker.compose.project.config_files": "/root/traefik/compose.yml",
                            "com.docker.compose.service": "traefik",
                        }
                    },
                }
            ]
        )
        self.assertFalse(pending["ready"])
        self.assertEqual(pending["file_source"], "/root/traefik/dynamic_conf.yml")
        self.assertEqual(pending["service"], "traefik")


class InstallationTests(unittest.TestCase):
    def alive(self, forward_id, listen, target):
        return {"forward_id": forward_id, "listen": listen, "target": target}

    def test_stale_records_follow_the_server_identity(self):
        sites = {"a.example": self.alive(1, 20000, 80), "b.example": self.alive(2, 20001, 81)}
        forwards = [
            {"id": 1, "listen_ports": {"start": 20000, "end": 20000}, "target_ports": {"start": 80}},
        ]
        stale = rift_site.stale_hosts
        # Same installation: nothing changes. Unreadable identity: nothing changes.
        self.assertEqual(stale("k1", "k1", sites, forwards), [])
        self.assertEqual(stale("k1", "", sites, forwards), [])
        # A new identity means a fresh installation: everything goes, even matching forwards.
        self.assertEqual(stale("k1", "k2", sites, forwards), ["a.example", "b.example"])
        # No stored identity (older helper): only records without a forward go.
        self.assertEqual(stale(None, "k2", sites, forwards), ["b.example"])

    def test_sync_removes_old_files_and_stores_the_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = Path(tmp) / "a.example.yml"
            old.write_text("x")
            state = {
                "container": "rift-server",
                "server_id": "k1",
                "traefik": {"dynamic_dir": tmp},
                "sites": {"a.example": {**self.alive(1, 20000, 80), "proxy": "traefik"}},
            }
            with mock.patch.object(rift_site, "STATE_PATH", Path(tmp) / "state" / "sites.json"), \
                    mock.patch.object(rift_site, "read_server_id", return_value="k2"):
                rift_site.sync_installation(state)
            self.assertFalse(old.exists())
            self.assertEqual(state["sites"], {})
            self.assertEqual(state["server_id"], "k2")

    def test_purge_removes_proxy_files_and_state_without_the_container(self):
        with tempfile.TemporaryDirectory() as tmp:
            dynamic = Path(tmp) / "dynamic"
            dynamic.mkdir()
            (dynamic / "a.example.yml").write_text("x")
            state_dir = Path(tmp) / "rift-site"
            state_dir.mkdir()
            state_path = state_dir / "sites.json"
            state = {
                "container": "rift-server",
                "traefik": {"dynamic_dir": str(dynamic)},
                "sites": {
                    "a.example": {**self.alive(1, 20000, 80), "proxy": "traefik"},
                    "n.example": {**self.alive(2, 20001, 81), "proxy": "npm"},
                },
            }
            state_path.write_text(json.dumps(state))
            with mock.patch.object(rift_site, "STATE_PATH", state_path), \
                    mock.patch.object(rift_site.subprocess, "run", side_effect=AssertionError("no processes")) as sp, \
                    mock.patch.object(rift_site, "run", side_effect=AssertionError("no processes")):
                rift_site.command_purge()
                sp.assert_not_called()
            self.assertFalse((dynamic / "a.example.yml").exists())
            self.assertFalse(state_dir.exists())


def make_tar(path, members, mode="w:gz"):
    """members: name -> bytes (a file), or None (a directory)."""
    with tarfile.open(path, mode) as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            if data is None:
                info.type = tarfile.DIRTYPE
                info.mode = 0o700
                archive.addfile(info)
            else:
                info.size = len(data)
                info.mode = 0o600
                archive.addfile(info, io.BytesIO(data))


MANIFEST = json.dumps({"format": 1, "created": "2026-11-01T10:00:00+00:00"}).encode()
SERVER_FILES = {
    "server": None,
    "server/state.db": b"db",
    "server/wireguard.key": b"key",
    "server/vpn": None,
    "server/vpn/a.key": b"device",
}


class ExportTests(unittest.TestCase):
    def forward(self, agent, listen, target, ingress="public"):
        return {
            "agent": agent,
            "listen_ip": "203.0.113.10",
            "listen_ports": {"start": listen, "end": listen},
            "target_ports": {"start": target, "end": target},
            "protocol": "tcp",
            "mode": "transparent",
            "ingress": ingress,
            "target_family": "v4",
            "enabled": True,
        }

    def test_sites_replace_the_forwards_they_made(self):
        core = {
            "format": 1,
            "agents": ["core"],
            "forwards": [
                self.forward("core", 2222, 22),
                self.forward("core", 20000, 8080, "local"),
                self.forward("core", 20001, 9000, "local"),
            ],
            "devices": [
                {
                    "name": "phone",
                    "enabled": True,
                    "panel": False,
                    "grants": [{"agent": "core", "access": "server"}],
                }
            ],
        }
        sites = {
            "app.example.org": {
                "agent": "core",
                "target": 8080,
                "listen": 20000,
                "proxy": "caddy",
                "forward_id": 2,
            }
        }
        document = rift_site.export_document(core, sites)
        self.assertEqual([f["listen_ports"]["start"] for f in document["forwards"]], [2222, 20001])
        self.assertEqual(
            document["sites"],
            [{"agent": "core", "host": "app.example.org", "port": 8080, "proxy": "caddy"}],
        )
        self.assertEqual(document["format"], 1)
        self.assertNotIn("forward_id", json.dumps(document))
        self.assertIn("2 forward(s)", rift_site.export_summary(document))
        self.assertIn("1 site(s)", rift_site.export_summary(document))
        self.assertEqual(rift_site.document_counts(document)["grants"], 1)

    def test_other_formats_are_refused(self):
        rift_site.check_export_format({"format": 1})
        with self.assertRaisesRegex(rift_site.SiteError, "format 2"):
            rift_site.check_export_format({"format": 2})
        with self.assertRaises(rift_site.SiteError):
            rift_site.check_export_format({"agents": []})
        with self.assertRaises(rift_site.SiteError):
            rift_site.check_export_format([])

    def test_export_writes_the_file_and_names_it_by_date(self):
        core = {"format": 1, "agents": ["core"], "forwards": [], "devices": []}
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(rift_site, "site_state", return_value={"sites": {}}), \
                mock.patch.object(rift_site, "rift", return_value=core) as call, \
                mock.patch.object(rift_site.Path, "cwd", return_value=Path(tmp)):
            rift_site.command_export([])
            call.assert_called_with({"sites": {}}, "export", "-")
            written = Path(tmp) / f"rift-export-{rift_site.today()}.json"
            self.assertEqual(json.loads(written.read_text())["sites"], [])
            rift_site.command_export([str(Path(tmp) / "mine.json")])
            self.assertTrue((Path(tmp) / "mine.json").exists())


class ImportTests(unittest.TestCase):
    def options(self, **extra):
        base = {"agents": [], "skip_agents": [], "map": [], "dry_run": False}
        base.update(extra)
        return base

    def entry(self, host, agent="core", port=8080, proxy="caddy"):
        return {"agent": agent, "host": host, "port": port, "proxy": proxy}

    def test_map_pairs_must_be_old_equals_new(self):
        self.assertEqual(rift_site.parse_map("core2=core"), ("core2", "core"))
        for bad in ("core2", "=core", "core2=", "a=b=c"):
            with self.assertRaises(Exception, msg=bad):
                rift_site.parse_map(bad)

    def test_sites_follow_the_agent_filters_and_mapping(self):
        agents = {"core": "active", "off": "disabled", "new": "pending"}
        entries = [
            self.entry("a.example.org", "core2"),
            self.entry("b.example.org", "core"),
            self.entry("c.example.org", "off"),
            self.entry("d.example.org", "new"),
            self.entry("e.example.org", "gone"),
        ]
        plan = rift_site.plan_site_import(
            entries, self.options(map=[("core2", "core")]), agents, {}, set()
        )
        self.assertEqual(
            [p["status"] for p in plan], ["create", "create", "skipped", "skipped", "skipped"]
        )
        self.assertEqual(plan[0]["agent"], "core")
        self.assertIn("rift enable agent off", plan[2]["detail"])
        self.assertIn("still open", plan[3]["detail"])
        self.assertIn("rift add agent gone", plan[4]["detail"])
        self.assertIn("--map gone=NAME", plan[4]["detail"])
        only = rift_site.plan_site_import(
            entries[:2], self.options(agents=["core"], map=[("core2", "off")]), agents, {}, set()
        )
        self.assertEqual([p["status"] for p in only], ["skipped", "create"])
        self.assertIn("--agent", only[0]["detail"])
        skip = rift_site.plan_site_import(
            entries[:2], self.options(skip_agents=["core"]), agents, {}, set()
        )
        self.assertEqual([p["status"] for p in skip], ["skipped", "skipped"])
        self.assertIn("--skip-agent", skip[1]["detail"])

    def test_existing_sites_are_present_or_a_conflict_but_never_changed(self):
        agents = {"core": "active"}
        sites = {
            "same.example.org": {"agent": "core", "target": 8080, "proxy": "caddy", "listen": 20000, "forward_id": 1},
            "other.example.org": {"agent": "core", "target": 9999, "proxy": "caddy", "listen": 20001, "forward_id": 2},
            "lost.example.org": {"agent": "core", "target": 8080, "proxy": "caddy", "listen": 20002, "forward_id": 3},
        }
        entries = [self.entry(h) for h in sites]
        plan = rift_site.plan_site_import(
            entries, self.options(), agents, sites, {"same.example.org", "other.example.org"}
        )
        self.assertEqual([p["status"] for p in plan], ["present", "failed", "failed"])
        self.assertIn("rift remove site other.example.org", plan[1]["detail"])
        bad = rift_site.plan_site_import(
            [self.entry("x.example.org", proxy="apache"), self.entry("not a host")],
            self.options(),
            agents,
            {},
            set(),
        )
        self.assertEqual([p["status"] for p in bad], ["failed", "failed"])

    def test_a_dry_run_creates_nothing_and_a_real_run_adds_each_site(self):
        agents = {"core": "active"}
        plan = rift_site.plan_site_import(
            [self.entry("a.example.org"), self.entry("b.example.org")],
            self.options(),
            agents,
            {},
            set(),
        )
        with mock.patch.object(rift_site, "command_add") as add:
            items = rift_site.import_sites({}, plan, True)
            add.assert_not_called()
        self.assertEqual([i["status"] for i in items], ["created", "created"])

        def fake_add(agent, host, port, proxy):
            if host == "b.example.org":
                raise rift_site.SiteError("caddy is not listening on port 443")
            print("https://" + host)
            print("DNS: " + host + " -> 203.0.113.10")

        with mock.patch.object(rift_site, "command_add", side_effect=fake_add):
            items = rift_site.import_sites({}, plan, False)
        self.assertEqual([i["status"] for i in items], ["created", "failed"])
        self.assertEqual(items[0]["detail"], "DNS: a.example.org -> 203.0.113.10")
        self.assertIn("port 443", items[1]["detail"])

    def test_the_report_is_grouped_like_the_server_report(self):
        items = [
            {"status": "created", "what": "forward core 22/tcp on 1.2.3.4", "detail": None},
            {"status": "created", "what": "device phone", "detail": "new keys"},
            {"status": "present", "what": "device tv", "detail": None},
            {"status": "skipped", "what": "3 entries for agent core2", "detail": "no such agent"},
            {"status": "failed", "what": "site a.example.org", "detail": "no proxy"},
        ]
        text = rift_site.render_import_report(items, True)
        for expected in (
            "Dry run: nothing was changed.",
            "Would create (2)\n  forward core 22/tcp on 1.2.3.4\n  device phone (new keys)",
            "Already present (1)\n  device tv",
            "Skipped (1)\n  3 entries for agent core2: no such agent",
            "Failed (1)\n  site a.example.org: no proxy",
        ):
            self.assertIn(expected, text)
        self.assertEqual(rift_site.render_import_report([], False), "Nothing to import.")
        self.assertTrue(rift_site.render_import_report(items, False).startswith("Created (2)"))

    def test_import_passes_the_file_and_filters_to_the_container(self):
        document = {"format": 1, "agents": [], "forwards": [], "devices": [], "sites": []}
        report = {"dry_run": True, "items": [{"status": "present", "what": "device tv", "detail": None}]}
        with tempfile.TemporaryDirectory() as tmp:
            export = Path(tmp) / "e.json"
            export.write_text(json.dumps(document))
            with mock.patch.object(rift_site, "site_state", return_value={"sites": {}}), \
                    mock.patch.object(rift_site, "rift_with_input", return_value=report) as call:
                rift_site.command_import(
                    [str(export), "--agent", "core", "--skip-agent", "x", "--map", "a=b", "--dry-run"]
                )
            args = call.call_args[0]
            self.assertEqual(
                args[2:],
                ("import", "-", "--agent", "core", "--skip-agent", "x", "--map", "a=b", "--dry-run"),
            )
            self.assertEqual(json.loads(args[1])["format"], 1)
            export.write_text(json.dumps({"format": 7}))
            with self.assertRaisesRegex(rift_site.SiteError, "format 7"):
                rift_site.command_import([str(export)])
            with self.assertRaises(rift_site.SiteError):
                rift_site.command_import([])


class BackupTests(unittest.TestCase):
    def test_paths_are_checked_and_the_volume_is_found(self):
        self.assertEqual(rift_site.tar_member_name("server/a"), "server/a")
        for bad in ("/etc/passwd", "server/../../etc"):
            with self.assertRaises(rift_site.SiteError):
                rift_site.tar_member_name(bad)
        volume = [
            {
                "Mounts": [
                    {"Type": "bind", "Source": "/etc/rift/config.toml", "Destination": "/etc/rift/config.toml"},
                    {
                        "Type": "volume",
                        "Name": "rift-vps_rift-state",
                        "Source": "/var/lib/docker/x",
                        "Destination": "/var/lib/rift",
                    },
                ]
            }
        ]
        self.assertEqual(rift_site.state_volume(volume), "rift-vps_rift-state")
        bind = [{"Mounts": [{"Type": "bind", "Source": "/srv/rift", "Destination": "/var/lib/rift"}]}]
        self.assertEqual(rift_site.state_volume(bind), "/srv/rift")
        with self.assertRaises(rift_site.SiteError):
            rift_site.state_volume([{"Mounts": []}])

    def producer(self, tmp, returncode=0, stderr=b"keep it private"):
        stream = Path(tmp) / "server.tar.gz"
        make_tar(stream, {**SERVER_FILES, "./": None, "other/x": b"no"})
        producer = mock.Mock()
        producer.stdout = io.BytesIO(stream.read_bytes())
        producer.stderr = io.BytesIO(stderr)
        producer.wait.return_value = returncode
        return producer

    def test_backup_adds_the_host_part_to_the_container_stream(self):
        with tempfile.TemporaryDirectory() as tmp:
            site_dir = Path(tmp) / "rift-site"
            site_dir.mkdir()
            (site_dir / "sites.json").write_text('{"sites": {}}')
            out = Path(tmp) / "out" / "b.tar.gz"
            out.parent.mkdir()
            state = {"container": "rift-server", "rift_config": "/c"}
            with mock.patch.object(rift_site, "site_state", return_value=state), \
                    mock.patch.object(rift_site, "STATE_PATH", site_dir / "sites.json"), \
                    mock.patch.object(
                        rift_site.subprocess, "Popen", return_value=self.producer(tmp)
                    ) as popen:
                rift_site.command_backup([str(out)])
            self.assertEqual(popen.call_args[0][0][-2:], ["backup", "-"])
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)
            with tarfile.open(out) as archive:
                names = archive.getnames()
            self.assertEqual(names[0], "rift-backup.json")
            self.assertIn("server/state.db", names)
            self.assertIn("server/vpn/a.key", names)
            self.assertIn("host/rift-site/sites.json", names)
            self.assertNotIn("other/x", names)
            manifest, files, host = rift_site.verify_backup(out)
            self.assertEqual((manifest["format"], files), (1, 3))
            self.assertEqual(host, {"sites.json": b'{"sites": {}}'})

    def test_a_failing_producer_leaves_no_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "b.tar.gz"
            failing = self.producer(tmp, 1, b"rift: there is no state to back up")
            state = {"container": "c", "rift_config": "/c"}
            with mock.patch.object(rift_site, "site_state", return_value=state), \
                    mock.patch.object(rift_site, "STATE_PATH", Path(tmp) / "none" / "sites.json"), \
                    mock.patch.object(rift_site.subprocess, "Popen", return_value=failing):
                with self.assertRaisesRegex(rift_site.SiteError, "no state to back up"):
                    rift_site.command_backup([str(out)])
            self.assertEqual(list(Path(tmp).glob("*b.tar.gz*")), [])

    def test_a_backup_is_checked_before_anything_is_touched(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = Path(tmp) / "good.tar.gz"
            make_tar(good, {"rift-backup.json": MANIFEST, **SERVER_FILES})
            self.assertEqual(rift_site.verify_backup(good)[1], 3)
            cases = {
                "no manifest": SERVER_FILES,
                "no database": {"rift-backup.json": MANIFEST, "server/wireguard.key": b"k"},
                "unsafe path": {"rift-backup.json": MANIFEST, **SERVER_FILES, "server/../x": b"x"},
                "stray path": {"rift-backup.json": MANIFEST, **SERVER_FILES, "etc/passwd": b"x"},
                "other format": {"rift-backup.json": b'{"format": 9}', **SERVER_FILES},
            }
            path = Path(tmp) / "bad.tar.gz"
            for label, members in cases.items():
                make_tar(path, members)
                with self.assertRaises(rift_site.SiteError, msg=label):
                    rift_site.verify_backup(path)
            path.write_bytes(b"not an archive")
            with self.assertRaises(rift_site.SiteError):
                rift_site.verify_backup(path)

    def run_restore(self, tmp, args, answer=None, tty=False):
        archive = Path(tmp) / "b.tar.gz"
        make_tar(
            archive,
            {
                "rift-backup.json": MANIFEST,
                **SERVER_FILES,
                "host/rift-site/sites.json": b'{"sites": {}}',
            },
        )
        loader = mock.Mock()
        loader.stdin = io.BytesIO()
        loader.stdin.close = lambda: None
        loader.stderr = io.BytesIO(b"")
        loader.wait.return_value = 0
        calls = []

        def fake_run(command, cwd=None):
            calls.append(command)
            if command[:2] == ["docker", "inspect"] and "--format" in command:
                return "sha256:image\n"
            if command[:2] == ["docker", "inspect"]:
                mounts = [{"Type": "volume", "Name": "vol", "Destination": "/var/lib/rift"}]
                return json.dumps([{"Mounts": mounts}])
            return ""

        site_dir = Path(tmp) / "rift-site"
        patches = [
            mock.patch.object(rift_site.os, "geteuid", return_value=0),
            mock.patch.object(rift_site, "run", side_effect=fake_run),
            mock.patch.object(rift_site, "load_state", return_value=None),
            mock.patch.object(rift_site, "STATE_PATH", site_dir / "sites.json"),
            mock.patch.object(rift_site, "wait_for_server", return_value=True),
            mock.patch.object(rift_site, "resync_sites", return_value=0),
            mock.patch.object(rift_site.subprocess, "Popen", return_value=loader),
            mock.patch.object(rift_site.sys.stdin, "isatty", return_value=tty),
            mock.patch.object(rift_site, "command_backup", side_effect=self.safety),
            mock.patch.object(rift_site.Path, "cwd", return_value=Path(tmp)),
            mock.patch("builtins.input", return_value=answer),
        ]
        for patch in patches:
            patch.start()
        self.addCleanup(mock.patch.stopall)
        rift_site.command_restore([str(archive), *args])
        return calls, loader, site_dir

    def safety(self, args):
        self.safety_paths.append(args[0])
        if getattr(self, "safety_fails", False):
            raise rift_site.SiteError("server not running")

    def setUp(self):
        self.safety_paths = []

    def test_restore_saves_the_current_state_first_and_stops_if_it_cannot(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.run_restore(tmp, ["--yes"])
            self.assertEqual(len(self.safety_paths), 1)
            self.assertIn("rift-before-restore-", self.safety_paths[0])
        self.safety_paths, self.safety_fails = [], True
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(rift_site.SiteError, "nothing was changed"):
                self.run_restore(tmp, ["--yes"])
        with tempfile.TemporaryDirectory() as tmp:
            calls, _, _ = self.run_restore(tmp, ["--yes", "--no-safety-backup"])
            self.assertIn(["docker", "stop", "-t", "60", "rift-server"], calls)

    def test_restore_needs_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(rift_site.SiteError, "--yes"):
                self.run_restore(tmp, [])
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(rift_site.SiteError, "cancelled"):
                self.run_restore(tmp, [], answer="no", tty=True)

    def test_restore_stops_writes_the_volume_and_starts_again(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls, loader, site_dir = self.run_restore(tmp, ["--yes"])
            steps = [c[1] for c in calls if c[:2] in (["docker", "stop"], ["docker", "start"])]
            self.assertEqual(steps, ["stop", "start"])
            sent = loader.stdin.getvalue()
            with tarfile.open(fileobj=io.BytesIO(sent), mode="r:") as sent_archive:
                self.assertEqual(
                    sorted(sent_archive.getnames()),
                    ["state.db", "vpn", "vpn/a.key", "wireguard.key"],
                )
                self.assertEqual({m.uid for m in sent_archive}, {0})
            self.assertEqual((site_dir / "sites.json").read_bytes(), b'{"sites": {}}')
            self.assertEqual((site_dir / "sites.json").stat().st_mode & 0o777, 0o600)

    def test_restore_refuses_without_root(self):
        with mock.patch.object(rift_site.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(rift_site.SiteError, "sudo"):
                rift_site.command_restore(["x.tar.gz", "--yes"])


class QueueTests(unittest.TestCase):
    def test_a_trailing_newline_is_not_a_valid_host_or_agent(self):
        self.assertFalse(rift_site.valid_host("a.example\n"))
        self.assertFalse(rift_site.valid_host("a.example\nserver {"))
        self.assertFalse(rift_site.valid_agent("core\n"))
        self.assertTrue(rift_site.valid_host("a.example"))

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.queue = Path(self.dir.name)
        self.counter = 0

    def request(self, document, raw=None):
        """Queues a request file; returns its id."""
        self.counter += 1
        name = f"{self.counter:032x}"
        if isinstance(document, dict) and raw is None and "id" not in document:
            document = {"id": name, **document}
        text = raw if raw is not None else json.dumps(document)
        path = self.queue / f"{name}.json"
        path.write_text(text, encoding="utf-8")
        # Oldest first by modification time.
        os.utime(path, (1000 + self.counter, 1000 + self.counter))
        return name

    def result(self, name):
        return json.loads((self.queue / f"{name}.result.json").read_text())

    def process(self, add=None, remove=None):
        with mock.patch.object(rift_site, "command_add", add or mock.Mock()) as a, mock.patch.object(
            rift_site, "command_rm", remove or mock.Mock()
        ) as r:
            count = rift_site.command_process_queue(self.queue, now=time.time())
        return count, a, r

    def good_add(self, **changes):
        return {"action": "add", "agent": "core", "host": "app.example.net", "port": 8080, **changes}

    def test_an_add_runs_the_add_logic_and_answers(self):
        def add(agent, host, port, proxy):
            print(f"https://{host}")

        mocked = mock.Mock(side_effect=add)
        name = self.request(self.good_add(proxy="caddy"))
        count, _, _ = self.process(add=mocked)
        self.assertEqual(count, 1)
        mocked.assert_called_once_with("core", "app.example.net", 8080, "caddy")
        self.assertEqual(
            self.result(name), {"id": name, "ok": True, "message": "https://app.example.net"}
        )
        self.assertFalse((self.queue / f"{name}.json").exists())

    def test_the_proxy_is_optional(self):
        self.request(self.good_add())
        _, add, _ = self.process()
        add.assert_called_once_with("core", "app.example.net", 8080, None)

    def test_a_remove_runs_the_remove_logic(self):
        name = self.request({"action": "remove", "host": "app.example.net"})
        _, add, remove = self.process()
        remove.assert_called_once_with("app.example.net")
        add.assert_not_called()
        self.assertTrue(self.result(name)["ok"])

    def test_a_failure_is_reported_with_the_helpers_message(self):
        failing = mock.Mock(side_effect=rift_site.SiteError("agent not found"))
        name = self.request(self.good_add())
        self.process(add=failing)
        answer = self.result(name)
        self.assertFalse(answer["ok"])
        self.assertEqual(answer["message"], "agent not found")
        self.assertFalse((self.queue / f"{name}.json").exists())

    def test_an_unexpected_error_does_not_stop_the_next_request(self):
        crashing = mock.Mock(side_effect=[KeyError("x"), None])
        first = self.request(self.good_add())
        second = self.request(self.good_add(host="b.example.net"))
        self.process(add=crashing)
        self.assertFalse(self.result(first)["ok"])
        self.assertTrue(self.result(second)["ok"])

    def test_requests_run_oldest_first(self):
        order = []
        add = mock.Mock(side_effect=lambda agent, host, port, proxy: order.append(host))
        for host in ("c.example.net", "a.example.net", "b.example.net"):
            self.request(self.good_add(host=host))
        self.process(add=add)
        self.assertEqual(order, ["c.example.net", "a.example.net", "b.example.net"])

    def test_bad_input_is_refused_and_never_executed(self):
        bad = [
            self.good_add(agent="x;id"),
            self.good_add(agent=""),
            self.good_add(agent=5),
            self.good_add(host="a b.net"),
            self.good_add(host="-a.net"),
            self.good_add(host="$(id).net"),
            self.good_add(host="a." * 130 + "net"),
            self.good_add(port=0),
            self.good_add(port=65536),
            self.good_add(port="80"),
            self.good_add(port=True),
            self.good_add(port=80.5),
            self.good_add(proxy="apache"),
            self.good_add(proxy=["caddy"]),
            self.good_add(command="id"),
            {"action": "add", "host": "a.net"},
            {"action": "remove", "host": "a.net", "agent": "core"},
            {"action": "remove", "host": "a.net;id"},
            {"action": "remove"},
            {"action": "restore", "host": "a.net"},
            {"action": "purge"},
            {"action": ["add"], "host": "a.net"},
            ["add"],
        ]
        names = [self.request(document) for document in bad]
        names += [
            self.request(None, raw="not json"),
            self.request(None, raw="\xff"),
            self.request(None, raw="x" * 5000),
        ]
        count, add, remove = self.process()
        self.assertEqual(count, len(names))
        add.assert_not_called()
        remove.assert_not_called()
        for name in names:
            answer = self.result(name)
            self.assertFalse(answer["ok"])
            self.assertTrue(answer["message"].startswith("request refused"), answer)
            self.assertFalse((self.queue / f"{name}.json").exists())

    def test_the_id_must_match_the_file_name(self):
        name = self.request({"id": "f" * 32, **self.good_add()})
        _, add, _ = self.process()
        add.assert_not_called()
        self.assertIn("id", self.result(name)["message"])

    def test_links_are_not_followed(self):
        outside = self.queue / "outside.txt"
        outside.write_text(json.dumps(self.good_add(id="0" * 32)))
        link = self.queue / f"{'0' * 32}.json"
        link.symlink_to(outside)
        _, add, _ = self.process()
        add.assert_not_called()
        self.assertFalse(link.is_symlink())
        self.assertTrue(outside.exists())
        self.assertFalse(self.result("0" * 32)["ok"])

    def test_other_files_are_left_alone(self):
        for name in ("notes.txt", f"{'a' * 32}.json.tmp", f"{'A' * 32}.json", "short.json"):
            (self.queue / name).write_text("{}")
        count, _, _ = self.process()
        self.assertEqual(count, 0)
        self.assertEqual(len(list(self.queue.iterdir())), 4)

    def test_old_results_are_cleaned_up(self):
        old = self.queue / f"{'1' * 32}.result.json"
        fresh = self.queue / f"{'2' * 32}.result.json"
        stale_tmp = self.queue / f"{'3' * 32}.result.json.tmp"
        for path in (old, fresh, stale_tmp):
            path.write_text("{}")
        long_ago = time.time() - 2 * 24 * 3600
        for path in (old, stale_tmp):
            os.utime(path, (long_ago, long_ago))
        self.process()
        self.assertFalse(old.exists())
        self.assertFalse(stale_tmp.exists())
        self.assertTrue(fresh.exists())

    def test_a_missing_queue_is_not_an_error(self):
        self.assertEqual(rift_site.command_process_queue(self.queue / "none"), 0)

    def test_the_command_is_wired_into_main(self):
        with mock.patch.object(rift_site, "command_process_queue") as run:
            rift_site.main(["rift-site", "process-queue"])
        run.assert_called_once_with()
        with self.assertRaises(rift_site.SiteError):
            rift_site.main(["rift-site", "process-queue", "extra"])


if __name__ == "__main__":
    unittest.main()
