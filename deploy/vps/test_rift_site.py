import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import re
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
            "app.example.net", "http://203.0.113.10:20000", "myresolver", "web", "websecure"
        )
        self.assertIn("rule: Host(`app.example.net`)", text)
        self.assertIn("certResolver: myresolver", text)
        self.assertIn("- web\n", text)
        self.assertIn("- websecure\n", text)
        self.assertIn("url: http://203.0.113.10:20000", text)

    def test_caddy_and_nginx_point_at_the_public_forward(self):
        self.assertEqual(
            rift_site.render_caddy("app.example.net", "http://203.0.113.10:20000"),
            "app.example.net {\n    reverse_proxy 203.0.113.10:20000\n}\n",
        )
        nginx = rift_site.render_nginx("app.example.net", "http://203.0.113.10:20000")
        self.assertIn("server_name app.example.net;", nginx)
        self.assertIn("proxy_pass http://203.0.113.10:20000;", nginx)

    def test_allowed_sources_reach_every_proxy(self):
        nets = ["203.0.113.7/32", "2001:db8::/48"]
        url = "http://203.0.113.10:20000"
        v3 = rift_site.render_traefik("app.example.net", url, "le", "web", "websecure", nets)
        self.assertEqual(v3.count("- rift-app-example-net-allow\n"), 2, "both routers")
        self.assertIn("ipAllowList:", v3)
        self.assertIn('- "2001:db8::/48"', v3)
        v2 = rift_site.render_traefik("app.example.net", url, "le", "web", "websecure", nets, 2)
        self.assertIn("ipWhiteList:", v2)
        self.assertNotIn("middlewares", rift_site.render_traefik("a.net", url, "le", "web", "websecure"))
        self.assertEqual(
            rift_site.render_caddy("app.example.net", url, nets),
            "app.example.net {\n"
            "    @rift_denied not remote_ip 203.0.113.7/32 2001:db8::/48\n"
            "    respond @rift_denied 403\n"
            "    reverse_proxy 203.0.113.10:20000\n}\n",
        )
        nginx = rift_site.render_nginx("app.example.net", url, nets)
        location = nginx.index("location / {")
        self.assertGreater(nginx.index("allow 203.0.113.7/32;"), location)
        self.assertLess(nginx.index("allow 2001:db8::/48;"), nginx.index("deny all;"))
        self.assertNotIn("deny", rift_site.render_nginx("a.net", url))
        payload = rift_site.npm_host_payload("a.net", "203.0.113.10", 20000, 0, nets)
        self.assertEqual(
            payload["advanced_config"], "allow 203.0.113.7/32;\nallow 2001:db8::/48;\ndeny all;\n"
        )
        self.assertEqual(rift_site.npm_host_payload("a.net", "203.0.113.10", 20000, 0)["advanced_config"], "")

    def test_traefik_major_version_comes_from_the_image_tag(self):
        def doc(image):
            return [{"Config": {"Image": image}}]

        self.assertEqual(rift_site.traefik_major(doc("traefik:v2.11")), 2)
        self.assertEqual(rift_site.traefik_major(doc("docker.io/library/traefik:2.10.7")), 2)
        self.assertEqual(rift_site.traefik_major(doc("traefik:v3.1")), 3)
        self.assertEqual(rift_site.traefik_major(doc("traefik:latest")), 3)
        self.assertEqual(rift_site.traefik_major(doc("traefik")), 3)
        self.assertEqual(rift_site.traefik_major(doc("registry:5000/traefik:v2.9")), 2)

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
            rift_site.missing_agent_message("node1", "rift: agent not found"),
        )
        self.assertEqual(
            rift_site.missing_agent_message("node1", "connection refused"),
            "connection refused",
        )

    def test_allocate_reuses_the_first_free_port(self):
        self.assertEqual(rift_site.allocate_port({20000, 20001}, 20000, 20999), 20002)
        with self.assertRaises(rift_site.SiteError):
            rift_site.allocate_port(set(range(20000, 20002)), 20000, 20001)


class EdgeTests(unittest.TestCase):
    def test_a_port_with_a_forward_suffix_is_explained(self):
        for port in ("8081/tcp/both", "8081/tcp", "0", "70000", "abc"):
            with mock.patch.object(rift_site, "load_state") as load:
                with self.assertRaises(rift_site.SiteError) as caught:
                    rift_site.command_add("node1", "app.example", port, None)
            load.assert_not_called()
            self.assertIn("PORT is the agent's port number, for example 8081", str(caught.exception))

    def test_a_port_from_the_queue_is_a_number_and_accepted(self):
        # The web panel and the terminal UI queue the port as a JSON number.
        with mock.patch.object(rift_site, "load_state", side_effect=rift_site.SiteError("stop")) as load:
            with self.assertRaises(rift_site.SiteError) as caught:
                rift_site.command_add("node1", "app.example", 8081, None)
        load.assert_called_once()
        self.assertEqual(str(caught.exception), "stop")

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

    def test_dns_check_says_whether_the_record_is_there(self):
        state = {"container": "rift-server", "public_ip": "203.0.113.5"}

        def lookup(answers):
            def resolve(host, *a, **k):
                if host not in answers:
                    raise OSError("NXDOMAIN")
                return [(2, 1, 6, "", (answers[host], 0))]
            return resolve

        with mock.patch.object(rift_site, "site_setting", lambda key, container="rift-server": "rift.example.net"):
            with mock.patch.object(rift_site.socket, "getaddrinfo", lookup({"rift.example.net": "203.0.113.5", "ok.example.net": "203.0.113.5"})):
                self.assertTrue(rift_site.dns_check("ok.example.net", state).endswith(": ok"))
                missing = rift_site.dns_check("new.example.net", state)
                self.assertTrue(missing.startswith("DNS: new.example.net -> 203.0.113.5"), missing)
                self.assertIn("missing. Create this A record", missing)
            with mock.patch.object(rift_site.socket, "getaddrinfo", lookup({"rift.example.net": "203.0.113.5", "old.example.net": "198.51.100.9"})):
                self.assertIn("wrong, it resolves to 198.51.100.9", rift_site.dns_check("old.example.net", state))

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
            ("1", "heim", "TCP", "10.0.0.207:20000", "8091", "v4", "local", "any", "transparent",
             "user", "enabled", "beszel.example.net (traefik)"),
        )
        self.assertEqual(rows[2][3], "[2001:db8::1]:1337-1339")
        self.assertEqual(rows[2][9:], ("user", "disabled", ""))
        # The managed forward of an internet exit says so.
        self.assertEqual(rows[3][9:], ("exit", "enabled", ""))
        forwards[1]["allow_from"] = ["2001:db8:1::/48", "2001:db8:2::7/128"]
        rows = rift_site.forward_rows(forwards, agents, sites)
        self.assertEqual(rows[2][7], "2001:db8:1::/48,2001:db8:2::7/128")

    def test_add_arguments_and_the_proxy_word(self):
        self.assertEqual(
            rift_site.parse_add_args(["node1", "a.example", "8081", "traefik"]),
            (["node1", "a.example", "8081"], "traefik", []),
        )
        self.assertEqual(
            rift_site.parse_add_args(
                ["node1", "a.example", "8081", "--allow-from", "203.0.113.7,198.51.100.9/24",
                 "caddy", "--allow-from=2001:db8::/48"]
            ),
            (["node1", "a.example", "8081"], "caddy",
             ["203.0.113.7/32", "198.51.100.0/24", "2001:db8::/48"]),
        )
        self.assertEqual(rift_site.parse_add_args(["node1", "a.example", "8081"])[1], None)
        with self.assertRaises(rift_site.SiteError) as typo:
            rift_site.parse_add_args(["node1", "a.example", "8081", "traefic"])
        self.assertIn("unknown proxy traefic", str(typo.exception))
        for bad in (
            ["node1", "a.example", "8081", "--proxy", "traefik"],
            ["node1", "a.example"],
            ["a", "b", "1", "npm", "x"],
            ["node1", "a.example", "8081", "--allow-from"],
            ["node1", "a.example", "8081", "--allow-from", "example.net"],
            ["node1", "a.example", "8081", "--allow-from", ","],
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
            "format": 2,
            "agents": ["node1"],
            "forwards": [
                self.forward("node1", 2222, 22),
                self.forward("node1", 20000, 8080, "local"),
                self.forward("node1", 20001, 9000, "local"),
            ],
            "devices": [
                {
                    "name": "phone",
                    "enabled": True,
                    "panel": False,
                    "grants": [{"agent": "node1", "access": "server"}],
                }
            ],
        }
        sites = {
            "app.example.org": {
                "agent": "node1",
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
            [{"agent": "node1", "host": "app.example.org", "port": 8080, "proxy": "caddy"}],
        )
        self.assertEqual(document["format"], 2)
        self.assertNotIn("forward_id", json.dumps(document))
        self.assertIn("2 forward(s)", rift_site.export_summary(document))
        self.assertIn("1 site(s)", rift_site.export_summary(document))
        self.assertEqual(rift_site.document_counts(document)["grants"], 1)

    def test_other_formats_are_refused(self):
        rift_site.check_export_format({"format": 2})
        with self.assertRaisesRegex(rift_site.SiteError, "format 1"):
            rift_site.check_export_format({"format": 1})
        with self.assertRaises(rift_site.SiteError):
            rift_site.check_export_format({"agents": []})
        with self.assertRaises(rift_site.SiteError):
            rift_site.check_export_format([])

    def test_export_writes_the_file_and_names_it_by_date(self):
        core = {"format": 2, "agents": ["node1"], "forwards": [], "devices": []}
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


class ExportFormatTests(unittest.TestCase):
    def test_the_host_reads_the_format_the_container_writes(self):
        # `rift export` in the container writes portable::FORMAT; the host imports only
        # EXPORT_FORMAT. They drifted apart once, and no export could be imported again.
        source = (Path(__file__).resolve().parents[2] / "src" / "portable.rs").read_text()
        match = re.search(r"pub const FORMAT: u32 = (\d+);", source)
        self.assertIsNotNone(match)
        self.assertEqual(int(match.group(1)), rift_site.EXPORT_FORMAT)


class ExportFieldTests(unittest.TestCase):
    def test_fields_of_the_server_pass_through_the_export(self):
        core = {"format": 2, "agents": ["node1"], "named_agents": ["node1"], "forwards": [],
                "devices": [{"name": "tablet", "names_off": True, "grants": []}]}
        document = rift_site.export_document(core, {})
        self.assertEqual(document["named_agents"], ["node1"])
        self.assertTrue(document["devices"][0]["names_off"])


class ImportTests(unittest.TestCase):
    def options(self, **extra):
        base = {"agents": [], "skip_agents": [], "map": [], "dry_run": False}
        base.update(extra)
        return base

    def entry(self, host, agent="node1", port=8080, proxy="caddy"):
        return {"agent": agent, "host": host, "port": port, "proxy": proxy}

    def test_map_pairs_must_be_old_equals_new(self):
        self.assertEqual(rift_site.parse_map("node2=node1"), ("node2", "node1"))
        for bad in ("node2", "=node1", "node2=", "a=b=c"):
            with self.assertRaises(Exception, msg=bad):
                rift_site.parse_map(bad)

    def test_sites_follow_the_agent_filters_and_mapping(self):
        agents = {"node1": "active", "node6": "disabled", "new": "pending"}
        entries = [
            self.entry("a.example.org", "node2"),
            self.entry("b.example.org", "node1"),
            self.entry("c.example.org", "node6"),
            self.entry("d.example.org", "new"),
            self.entry("e.example.org", "gone"),
        ]
        plan = rift_site.plan_site_import(
            entries, self.options(map=[("node2", "node1")]), agents, {}, set()
        )
        self.assertEqual(
            [p["status"] for p in plan], ["create", "create", "skipped", "skipped", "skipped"]
        )
        self.assertEqual(plan[0]["agent"], "node1")
        self.assertIn("rift enable agent node6", plan[2]["detail"])
        self.assertIn("still open", plan[3]["detail"])
        self.assertIn("rift add agent gone", plan[4]["detail"])
        self.assertIn("--map gone=NAME", plan[4]["detail"])
        only = rift_site.plan_site_import(
            entries[:2], self.options(agents=["node1"], map=[("node2", "node6")]), agents, {}, set()
        )
        self.assertEqual([p["status"] for p in only], ["skipped", "create"])
        self.assertIn("--agent", only[0]["detail"])
        skip = rift_site.plan_site_import(
            entries[:2], self.options(skip_agents=["node1"]), agents, {}, set()
        )
        self.assertEqual([p["status"] for p in skip], ["skipped", "skipped"])
        self.assertIn("--skip-agent", skip[1]["detail"])

    def test_existing_sites_are_present_or_a_conflict_but_never_changed(self):
        agents = {"node1": "active"}
        sites = {
            "same.example.org": {"agent": "node1", "target": 8080, "proxy": "caddy", "listen": 20000, "forward_id": 1},
            "other.example.org": {"agent": "node1", "target": 9999, "proxy": "caddy", "listen": 20001, "forward_id": 2},
            "lost.example.org": {"agent": "node1", "target": 8080, "proxy": "caddy", "listen": 20002, "forward_id": 3},
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
        agents = {"node1": "active"}
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

        def fake_add(agent, host, port, proxy, allow_from):
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
            {"status": "created", "what": "forward node1 22/tcp on 1.2.3.4", "detail": None},
            {"status": "created", "what": "device phone", "detail": "new keys"},
            {"status": "present", "what": "device tv", "detail": None},
            {"status": "skipped", "what": "3 entries for agent node2", "detail": "no such agent"},
            {"status": "failed", "what": "site a.example.org", "detail": "no proxy"},
        ]
        text = rift_site.render_import_report(items, True)
        for expected in (
            "Dry run: nothing was changed.",
            "Would create (2)\n  forward node1 22/tcp on 1.2.3.4\n  device phone (new keys)",
            "Already present (1)\n  device tv",
            "Skipped (1)\n  3 entries for agent node2: no such agent",
            "Failed (1)\n  site a.example.org: no proxy",
        ):
            self.assertIn(expected, text)
        self.assertEqual(rift_site.render_import_report([], False), "Nothing to import.")
        self.assertTrue(rift_site.render_import_report(items, False).startswith("Created (2)"))

    def test_import_passes_the_file_and_filters_to_the_container(self):
        document = {"format": 2, "agents": [], "forwards": [], "devices": [], "sites": []}
        report = {"dry_run": True, "items": [{"status": "present", "what": "device tv", "detail": None}]}
        with tempfile.TemporaryDirectory() as tmp:
            export = Path(tmp) / "e.json"
            export.write_text(json.dumps(document))
            with mock.patch.object(rift_site, "site_state", return_value={"sites": {}}), \
                    mock.patch.object(rift_site, "rift_with_input", return_value=report) as call:
                rift_site.command_import(
                    [str(export), "--agent", "node1", "--skip-agent", "x", "--map", "a=b", "--dry-run"]
                )
            args = call.call_args[0]
            self.assertEqual(
                args[2:],
                ("import", "-", "--agent", "node1", "--skip-agent", "x", "--map", "a=b", "--dry-run"),
            )
            self.assertEqual(json.loads(args[1])["format"], 2)
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


class ProxyCommandTests(unittest.TestCase):
    def run_main(self, *args):
        saved = {}
        with mock.patch.object(rift_site, "load_state", return_value=rift_site.default_state("203.0.113.10")), \
                mock.patch.object(rift_site, "save_state", side_effect=lambda s: saved.update(s)), \
                contextlib.redirect_stdout(io.StringIO()):
            rift_site.main(["rift-site", "proxy", *args])
        return saved

    def test_caddy_in_a_container_is_reloaded_there(self):
        state = self.run_main("caddy", "--container", "rift-caddy", "--sites-dir", "/opt/rift-caddy/sites")
        self.assertEqual(state["proxy"], "caddy")
        self.assertEqual(state["caddy"]["sites_dir"], "/opt/rift-caddy/sites")
        self.assertEqual(
            state["caddy"]["reload"],
            ["docker", "exec", "rift-caddy", "caddy", "reload", "--config", "/etc/caddy/Caddyfile"],
        )
        # Without the options the host's Caddy stays the default.
        self.assertEqual(self.run_main("caddy")["caddy"]["reload"][0], "caddy")

    def test_container_options_are_checked(self):
        for args in (
            ("traefik", "--container", "x", "--sites-dir", "/x"),
            ("caddy", "--container", "a;b", "--sites-dir", "/x"),
            ("caddy", "--container", "rift-caddy", "--sites-dir", "relative"),
            ("caddy", "--container", "rift-caddy", "--sites-dir", "/opt/../etc"),
            ("caddy", "--container", "rift-caddy"),
            ("caddy", "--name", "x", "--sites-dir", "/x"),
        ):
            with self.assertRaises(rift_site.SiteError, msg=args):
                self.run_main(*args)


class CaddyMoveTests(unittest.TestCase):
    """`rift proxy caddy` with --host, or --container and --sites-dir, moves Caddy's routes."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.root = Path(self.dir.name)
        (self.root / "old").mkdir()
        self.state = rift_site.default_state("203.0.113.10")
        self.state["proxy"] = "caddy"
        self.state["caddy"] = {
            "sites_dir": str(self.root / "old"),
            "reload": ["docker", "exec", "old-caddy", "caddy", "reload", "--config", "/etc/caddy/Caddyfile"],
        }
        self.state["sites"] = {
            "a.example.net": {"agent": "node1", "target": 8080, "listen": 20000, "proxy": "caddy",
                              "forward_id": 3, "allow_from": ["198.51.100.7/32"]},
            "b.example.net": {"agent": "node1", "target": 9000, "listen": 20001, "proxy": "traefik",
                              "forward_id": 4},
        }
        self.state["panel"] = {"host": "panel.example.net", "proxy": "caddy"}
        for host in ("a.example.net", "panel.example.net"):
            (self.root / "old" / f"{host}.caddy").write_text("old")
        self.saved = []
        self.runs = []

    def proxy(self, *args, fail_on=None):
        def run(command, *rest, **kwargs):
            self.runs.append(command)
            if fail_on and command[:3] == fail_on:
                raise rift_site.SiteError("reload failed")
            return ""

        with mock.patch.object(rift_site, "load_state", return_value=self.state), \
                mock.patch.object(rift_site, "save_state", side_effect=lambda s: self.saved.append(json.loads(json.dumps(s)))), \
                mock.patch.object(rift_site, "run", side_effect=run), \
                mock.patch.object(rift_site, "rift", return_value={"port": 8090, "server_ipv4": "10.13.0.1"}), \
                contextlib.redirect_stdout(io.StringIO()):
            rift_site.main(["rift-site", "proxy", "caddy", *args])

    def test_a_new_container_gets_the_routes(self):
        new = self.root / "new"
        self.proxy("--container", "new-caddy", "--sites-dir", str(new))
        self.assertEqual(self.saved[-1]["caddy"]["sites_dir"], str(new))
        self.assertIn("203.0.113.10:20000", (new / "a.example.net.caddy").read_text())
        self.assertIn("198.51.100.7/32", (new / "a.example.net.caddy").read_text())
        # The panel route of a Caddy in Docker goes to the tunnel address.
        self.assertIn("10.13.0.1:8090", (new / "panel.example.net.caddy").read_text())
        self.assertFalse((new / "b.example.net.caddy").exists())
        self.assertEqual(list((self.root / "old").iterdir()), [])
        self.assertEqual(self.runs[0][:3], ["docker", "exec", "new-caddy"])
        self.assertEqual(self.runs[1][:3], ["docker", "exec", "old-caddy"])

    def test_host_resets_caddy_to_the_host(self):
        host_dir = self.root / "host"
        real = rift_site.default_state

        def patched(ip):
            state = real(ip)
            state["caddy"]["sites_dir"] = str(host_dir)
            return state

        with mock.patch.object(rift_site, "default_state", side_effect=patched):
            self.proxy("--host")
        self.assertEqual(self.saved[-1]["caddy"]["reload"][0], "caddy")
        # A Caddy on the host reaches the panel on loopback.
        self.assertIn("127.0.0.1:8090", (host_dir / "panel.example.net.caddy").read_text())
        self.assertTrue((host_dir / "a.example.net.caddy").exists())

    def test_without_options_caddy_stays_where_it_is(self):
        self.proxy()
        self.assertEqual(self.saved[-1]["caddy"]["sites_dir"], str(self.root / "old"))
        self.assertEqual(self.runs, [])
        self.assertEqual((self.root / "old" / "a.example.net.caddy").read_text(), "old")

    def test_a_failed_reload_keeps_the_old_caddy(self):
        new = self.root / "new"
        with self.assertRaises(rift_site.SiteError):
            self.proxy("--container", "new-caddy", "--sites-dir", str(new), fail_on=["docker", "exec", "new-caddy"])
        self.assertEqual(self.saved, [])
        self.assertEqual(list(new.iterdir()), [])
        self.assertEqual((self.root / "old" / "a.example.net.caddy").read_text(), "old")
        self.assertEqual(self.state["caddy"]["sites_dir"], str(self.root / "old"))

    def test_host_excludes_the_container_options(self):
        for args in (("--host", "--container", "x", "--sites-dir", "/x"), ("--host", "--host")):
            with self.assertRaises(rift_site.SiteError, msg=args):
                self.proxy(*args)
        with self.assertRaises(rift_site.SiteError), contextlib.redirect_stdout(io.StringIO()):
            rift_site.main(["rift-site", "proxy", "traefik", "--host"])


class MigrateTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        root = Path(self.dir.name)
        self.state = rift_site.default_state("203.0.113.10")
        self.state["caddy"]["sites_dir"] = str(root / "caddy")
        self.state["traefik"]["dynamic_dir"] = str(root / "dynamic")
        self.state["traefik"]["major"] = 3
        for name in ("caddy", "dynamic"):
            (root / name).mkdir()
        self.state["sites"] = {
            "a.example.net": {"agent": "node1", "target": 8080, "listen": 20000, "proxy": "caddy", "forward_id": 3},
            "b.example.net": {"agent": "node1", "target": 9000, "listen": 20001, "proxy": "caddy",
                              "forward_id": 4, "allow_from": ["198.51.100.7/32"]},
        }
        for host in self.state["sites"]:
            (root / "caddy" / f"{host}.caddy").write_text("old")
        self.saved = []

    def migrate(self, new, **patches):
        defaults = {
            "load_state": mock.Mock(return_value=self.state),
            "save_state": mock.Mock(side_effect=lambda s: self.saved.append(json.loads(json.dumps(s)))),
            "sync_installation": mock.Mock(),
            "capture_edge": mock.Mock(return_value=([], [])),
            "require_edge": mock.Mock(),
            "ensure_traefik_provider": mock.Mock(return_value=None),
            "run": mock.Mock(return_value=""),
            "rift": mock.Mock(side_effect=AssertionError("forwards must not change")),
        }
        defaults.update(patches)
        out = io.StringIO()
        with contextlib.ExitStack() as stack:
            for name, value in defaults.items():
                stack.enter_context(mock.patch.object(rift_site, name, value))
            stack.enter_context(contextlib.redirect_stdout(out))
            try:
                rift_site.command_migrate_sites(new)
            except rift_site.SiteError as error:
                return out.getvalue(), error
        return out.getvalue(), None

    def test_sites_move_to_another_file_proxy_and_keep_their_forward(self):
        out, error = self.migrate("traefik")
        self.assertIsNone(error, out)
        dynamic = Path(self.state["traefik"]["dynamic_dir"])
        self.assertIn("url: http://203.0.113.10:20000", (dynamic / "a.example.net.yml").read_text())
        self.assertIn("ipAllowList", (dynamic / "b.example.net.yml").read_text())
        self.assertEqual(list(Path(self.state["caddy"]["sites_dir"]).iterdir()), [])
        final = self.saved[-1]["sites"]
        self.assertEqual({h: s["proxy"] for h, s in final.items()}, {"a.example.net": "traefik", "b.example.net": "traefik"})
        self.assertEqual(final["a.example.net"]["forward_id"], 3)
        self.assertIn("Moved to traefik (2)", out)

    def test_sites_move_to_nginx_proxy_manager(self):
        publish = mock.Mock(side_effect=[{"host_id": 7, "note": None}, {"host_id": 8, "note": "no TLS"}])
        out, error = self.migrate("npm", npm_publish=publish)
        self.assertIsNone(error, out)
        publish.assert_any_call(self.state, "b.example.net", 20001, ["198.51.100.7/32"])
        final = self.saved[-1]["sites"]
        self.assertEqual((final["a.example.net"]["npm_host_id"], final["b.example.net"]["npm_host_id"]), (7, 8))
        self.assertIn("Note: b.example.net: no TLS", out)

    def test_an_old_nginx_proxy_manager_is_not_asked(self):
        for site in self.state["sites"].values():
            site["proxy"], site["npm_host_id"] = "npm", 5
        removed = mock.Mock()
        out, error = self.migrate("caddy", npm_remove=removed, npm_request=mock.Mock(side_effect=AssertionError))
        self.assertIsNone(error, out)
        removed.assert_not_called()
        self.assertNotIn("npm_host_id", self.saved[-1]["sites"]["a.example.net"])

    def test_one_failing_site_does_not_stop_the_others(self):
        calls = []

        def reload(state, proxy, host):
            calls.append(host)
            if host == "a.example.net":
                raise rift_site.SiteError("caddy reload failed")

        self.state["sites"]["a.example.net"]["proxy"] = "traefik"
        self.state["sites"]["b.example.net"]["proxy"] = "traefik"
        out, error = self.migrate("caddy", reload_proxy=reload)
        self.assertIsNotNone(error)
        self.assertIn("a.example.net: caddy reload failed", out)
        final = self.saved[-1]["sites"]
        self.assertEqual((final["a.example.net"]["proxy"], final["b.example.net"]["proxy"]), ("traefik", "caddy"))
        caddy = Path(self.state["caddy"]["sites_dir"])
        self.assertFalse((caddy / "a.example.net.caddy").exists(), "a failed site left its new file behind")

    def test_the_new_proxy_must_hold_443(self):
        out, error = self.migrate("npm", require_edge=mock.Mock(side_effect=rift_site.SiteError("caddy holds port 443, not npm")))
        self.assertIn("holds port 443", str(error))
        self.assertEqual(self.saved, [])


class PanelRouteTests(unittest.TestCase):
    STATUS = {"enabled": True, "port": 8090, "server_ipv4": "10.13.0.1", "control": "public"}

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        root = Path(self.dir.name)
        self.state = rift_site.default_state("203.0.113.10")
        self.state["traefik"]["dynamic_dir"] = str(root / "dynamic")
        self.state["caddy"]["sites_dir"] = str(root / "caddy")
        self.saved = []

    def route(self, *args, **patches):
        defaults = {
            "load_state": mock.Mock(return_value=self.state),
            "save_state": mock.Mock(side_effect=lambda s: self.saved.append(json.loads(json.dumps(s)))),
            "sync_installation": mock.Mock(),
            "capture_edge": mock.Mock(return_value=([], [])),
            "require_edge": mock.Mock(),
            "ensure_traefik_provider": mock.Mock(return_value=None),
            "run": mock.Mock(return_value=""),
            "rift": mock.Mock(return_value=dict(self.STATUS)),
            "dns_check": mock.Mock(return_value="DNS: ok"),
        }
        defaults.update(patches)
        out = io.StringIO()
        with contextlib.ExitStack() as stack:
            for name, value in defaults.items():
                stack.enter_context(mock.patch.object(rift_site, name, value))
            stack.enter_context(contextlib.redirect_stdout(out))
            rift_site.command_panel_route(list(args))
        return out.getvalue()

    def test_traefik_reaches_the_panel_on_the_tunnel_address_and_redirects_http(self):
        out = self.route("panel.example.net")
        text = (Path(self.state["traefik"]["dynamic_dir"]) / "panel.example.net.yml").read_text()
        self.assertIn("url: http://10.13.0.1:8090", text)
        self.assertIn("redirectScheme", text)
        self.assertIn("certResolver: myresolver", text)
        self.assertEqual(self.saved[-1]["panel"], {"host": "panel.example.net", "proxy": "traefik"})
        self.assertIn("https://panel.example.net", out)

    def test_caddy_on_the_host_uses_loopback_and_in_a_container_the_tunnel(self):
        self.state["proxy"] = "caddy"
        self.route("panel.example.net")
        path = Path(self.state["caddy"]["sites_dir"]) / "panel.example.net.caddy"
        self.assertIn("reverse_proxy 127.0.0.1:8090", path.read_text())
        self.state["caddy"]["reload"] = ["docker", "exec", "rift-caddy", "caddy", "reload"]
        self.route("panel.example.net")
        self.assertIn("reverse_proxy 10.13.0.1:8090", path.read_text())

    def test_nginx_proxy_manager_forwards_to_the_tunnel_address(self):
        self.state["proxy"] = "npm"
        publish = mock.Mock(return_value={"host_id": 9, "note": None})
        self.route("panel.example.net", npm_publish=publish)
        publish.assert_called_once_with(self.state, "panel.example.net", 8090, (), "10.13.0.1")
        self.assertEqual(self.saved[-1]["panel"]["npm_host_id"], 9)

    def test_off_removes_the_route(self):
        self.route("panel.example.net")
        path = Path(self.state["traefik"]["dynamic_dir"]) / "panel.example.net.yml"
        self.assertTrue(path.exists())
        self.state["panel"] = self.saved[-1]["panel"]
        self.route("--off")
        self.assertFalse(path.exists())
        self.assertNotIn("panel", self.saved[-1])

    def test_a_site_name_or_a_panel_that_is_off_is_refused(self):
        self.state["sites"]["app.example.net"] = {"agent": "node1", "target": 80, "listen": 20000, "proxy": "traefik"}
        with self.assertRaisesRegex(rift_site.SiteError, "is a site"):
            self.route("app.example.net")
        with self.assertRaisesRegex(rift_site.SiteError, "panel is off"):
            self.route("panel.example.net", rift=mock.Mock(return_value={"enabled": False}))
        with self.assertRaises(rift_site.SiteError):
            self.route("not a domain")

    def test_the_route_moves_with_the_sites(self):
        self.state["panel"] = {"host": "panel.example.net", "proxy": "traefik"}
        old = Path(self.state["traefik"]["dynamic_dir"]) / "panel.example.net.yml"
        old.parent.mkdir(parents=True)
        old.write_text("old")
        out = io.StringIO()
        with mock.patch.object(rift_site, "load_state", return_value=self.state), \
                mock.patch.object(rift_site, "save_state", side_effect=lambda s: self.saved.append(json.loads(json.dumps(s)))), \
                mock.patch.object(rift_site, "sync_installation"), \
                mock.patch.object(rift_site, "capture_edge", return_value=([], [])), \
                mock.patch.object(rift_site, "require_edge"), \
                mock.patch.object(rift_site, "run", return_value=""), \
                mock.patch.object(rift_site, "rift", return_value=dict(self.STATUS)), \
                contextlib.redirect_stdout(out):
            rift_site.command_migrate_sites("caddy")
        self.assertFalse(old.exists())
        self.assertIn("reverse_proxy 127.0.0.1:8090", (Path(self.state["caddy"]["sites_dir"]) / "panel.example.net.caddy").read_text())
        self.assertEqual(self.saved[-1]["panel"], {"host": "panel.example.net", "proxy": "caddy"})
        self.assertIn("panel panel.example.net (from traefik)", out.getvalue())


class RemoveTests(unittest.TestCase):
    def test_remove_says_what_it_removed(self):
        state = {"sites": {"pd.example.net": {"agent": "PP", "proxy": "traefik", "forward_id": 9}}}
        out = io.StringIO()
        with mock.patch.object(rift_site, "load_state", return_value=state), \
                mock.patch.object(rift_site, "sync_installation"), \
                mock.patch.object(rift_site, "remove_site_config", return_value=None), \
                mock.patch.object(rift_site, "remove_forward") as remove_forward, \
                mock.patch.object(rift_site, "save_state"), \
                mock.patch.object(rift_site, "reload_proxy"), \
                contextlib.redirect_stdout(out):
            rift_site.command_rm("pd.example.net")
        remove_forward.assert_called_once_with(state, 9)
        self.assertEqual(
            out.getvalue().strip(),
            "Site pd.example.net removed: traefik configuration and forward 9 (agent PP).",
        )
        self.assertNotIn("pd.example.net", state["sites"])


class QueueTests(unittest.TestCase):
    def test_a_trailing_newline_is_not_a_valid_host_or_agent(self):
        self.assertFalse(rift_site.valid_host("a.example\n"))
        self.assertFalse(rift_site.valid_host("a.example\nserver {"))
        self.assertFalse(rift_site.valid_agent("node1\n"))
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
        return {"action": "add", "agent": "node1", "host": "app.example.net", "port": 8080, **changes}

    def test_an_add_runs_the_add_logic_and_answers(self):
        def add(agent, host, port, proxy, allow_from):
            print(f"https://{host}")

        mocked = mock.Mock(side_effect=add)
        name = self.request(self.good_add(proxy="caddy"))
        count, _, _ = self.process(add=mocked)
        self.assertEqual(count, 1)
        mocked.assert_called_once_with("node1", "app.example.net", 8080, "caddy", [])
        self.assertEqual(
            self.result(name), {"id": name, "ok": True, "message": "https://app.example.net"}
        )
        self.assertFalse((self.queue / f"{name}.json").exists())

    def test_the_proxy_is_optional(self):
        self.request(self.good_add())
        _, add, _ = self.process()
        add.assert_called_once_with("node1", "app.example.net", 8080, None, [])

    def test_allowed_sources_are_checked_and_passed_on(self):
        self.request(self.good_add(allow_from=["203.0.113.7", "198.51.100.0/24"]))
        _, add, _ = self.process()
        add.assert_called_once_with(
            "node1", "app.example.net", 8080, None, ["203.0.113.7/32", "198.51.100.0/24"]
        )
        for bad in ("203.0.113.7", ["example.net"], [7], ["1.2.3.4; deny"]):
            name = self.request(self.good_add(allow_from=bad))
            _, add, _ = self.process()
            add.assert_not_called()
            self.assertFalse(self.result(name)["ok"])

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
        add = mock.Mock(side_effect=lambda agent, host, port, proxy, allow_from: order.append(host))
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
            {"action": "remove", "host": "a.net", "agent": "node1"},
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

    def test_an_export_leaves_the_file_of_the_command_line_next_to_the_result(self):
        document = {"format": 2, "agents": ["node1"], "forwards": [], "devices": [], "sites": []}
        data = (json.dumps(document, indent=2) + "\n").encode()
        name = self.request({"action": "export"})
        with mock.patch.object(rift_site, "export_file", return_value=(document, data)):
            self.process()
        result = self.result(name)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["file"], f"rift-export-{rift_site.today()}.json")
        self.assertIn("1 agent(s)", result["message"])
        path = self.queue / f"{name}.data"
        self.assertEqual(path.read_bytes(), data)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_a_backup_is_written_next_to_the_result(self):
        def backup(path):
            Path(path).write_bytes(b"archive")
            os.chmod(path, 0o600)

        name = self.request({"action": "backup"})
        with mock.patch.object(rift_site, "write_backup", side_effect=backup) as write:
            self.process()
        write.assert_called_once_with(self.queue / f"{name}.data")
        result = self.result(name)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["file"], f"rift-backup-{rift_site.today()}.tar.gz")
        self.assertEqual((self.queue / f"{name}.data").read_bytes(), b"archive")

    def kept_files(self):
        files = Path(self.dir.name) / "files"
        return files, mock.patch.object(rift_site, "FILES_DIR", files)

    def test_an_export_with_keep_is_saved_on_the_host(self):
        document = {"format": 2, "agents": [], "forwards": [], "devices": [], "sites": []}
        data = b"{}\n"
        files, patch = self.kept_files()
        name = self.request({"action": "export", "keep": True})
        with patch, mock.patch.object(rift_site, "export_file", return_value=(document, data)):
            self.process()
        result = self.result(name)
        self.assertTrue(result["ok"], result)
        self.assertNotIn("file", result)
        self.assertFalse((self.queue / f"{name}.data").exists())
        saved = list(files.iterdir())
        self.assertEqual(len(saved), 1)
        self.assertRegex(saved[0].name, r"^rift-export-\d{4}-\d{2}-\d{2}-\d{6}\.json$")
        self.assertEqual(saved[0].read_bytes(), data)
        self.assertEqual(saved[0].stat().st_mode & 0o777, 0o600)
        self.assertEqual(files.stat().st_mode & 0o777, 0o700)
        self.assertIn(f"Saved on the host: {saved[0]}", result["message"])

    def test_a_backup_with_keep_is_saved_and_old_ones_are_pruned(self):
        files, patch = self.kept_files()
        files.mkdir()
        for day in range(1, 26):
            (files / f"rift-backup-2026-01-{day:02d}-120000.tar.gz").write_bytes(b"old")
        (files / "my-own.tar.gz").write_bytes(b"mine")

        def backup(path):
            Path(path).write_bytes(b"archive")

        name = self.request({"action": "backup", "keep": True})
        with patch, mock.patch.object(rift_site, "write_backup", side_effect=backup):
            self.process()
        self.assertTrue(self.result(name)["ok"])
        backups = sorted(p.name for p in files.iterdir() if p.name.startswith("rift-backup-"))
        self.assertEqual(len(backups), rift_site.FILES_KEPT)
        self.assertNotIn("rift-backup-2026-01-01-120000.tar.gz", backups)
        self.assertTrue((files / "my-own.tar.gz").exists())

    def test_keep_must_be_a_boolean(self):
        files, patch = self.kept_files()
        name = self.request({"action": "export", "keep": "yes"})
        with patch, mock.patch.object(rift_site, "export_file") as export:
            self.process()
        export.assert_not_called()
        self.assertFalse(self.result(name)["ok"])
        self.assertFalse(files.exists())

    def test_a_failed_backup_leaves_no_file(self):
        def backup(path):
            Path(path).write_bytes(b"half")
            raise rift_site.SiteError("the container is not running")

        name = self.request({"action": "backup"})
        with mock.patch.object(rift_site, "write_backup", side_effect=backup):
            self.process()
        result = self.result(name)
        self.assertFalse(result["ok"])
        self.assertNotIn("file", result)
        self.assertFalse((self.queue / f"{name}.data").exists())

    def test_an_import_runs_the_import_of_the_command_line(self):
        document = {"format": 2, "agents": [], "forwards": [], "devices": [], "sites": []}
        items = [{"status": "created", "what": "device tv", "detail": None}]
        name = self.request(
            {"action": "import", "document": document, "dry_run": True, "map": ["node2=node1"]}
        )
        with mock.patch.object(rift_site, "run_import", return_value=items) as run:
            self.process()
        raw, options = run.call_args[0]
        self.assertEqual(json.loads(raw), document)
        self.assertEqual(
            options, {"agents": [], "skip_agents": [], "map": [("node2", "node1")], "dry_run": True}
        )
        result = self.result(name)
        self.assertTrue(result["ok"], result)
        self.assertIn("Would create (1)", result["message"])
        report = json.loads((self.queue / f"{name}.data").read_text())
        self.assertEqual(report, {"dry_run": True, "items": items})

    def test_import_requests_are_checked(self):
        good = {"action": "import", "document": {"format": 2}, "dry_run": False}
        for bad in (
            {**good, "document": [1]},
            {**good, "dry_run": "yes"},
            {**good, "map": "a=b"},
            {**good, "map": ["a"]},
            {**good, "map": ["a=b c"]},
            {**good, "extra": 1},
            {"action": "export", "extra": 1},
            {"action": "backup", "path": "/etc/shadow"},
        ):
            name = self.request(bad)
            with mock.patch.object(rift_site, "run_import") as run, \
                    mock.patch.object(rift_site, "write_backup") as backup:
                self.process()
            run.assert_not_called()
            backup.assert_not_called()
            self.assertFalse(self.result(name)["ok"], bad)

    def test_only_an_import_may_be_large(self):
        big = "x" * (rift_site.QUEUE_MAX_BYTES + 10)
        name = self.request({"action": "add", "agent": "node1", "host": "a.example", "port": 1, "proxy": None,
                             "allow_from": [big]})
        self.process()
        self.assertIn("too large", self.result(name)["message"])
        document = {"format": 2, "agents": [], "forwards": [], "devices": [], "sites": [], "pad": big}
        name = self.request({"action": "import", "document": document, "dry_run": True})
        with mock.patch.object(rift_site, "run_import", return_value=[]):
            self.process()
        self.assertTrue(self.result(name)["ok"])

    def test_fetched_files_expire_sooner_than_results(self):
        now = time.time()
        data = self.queue / f"{'a' * 32}.data"
        data.write_bytes(b"keys")
        result = self.queue / f"{'a' * 32}.result.json"
        result.write_text("{}")
        old = now - rift_site.QUEUE_DATA_AGE - 1
        os.utime(data, (old, old))
        os.utime(result, (old, old))
        rift_site.clean_queue_results(self.queue, now)
        self.assertFalse(data.exists())
        self.assertTrue(result.exists())

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


class ListFilterTests(unittest.TestCase):
    def test_words_and_agents_narrow_the_sites(self):
        sites = {
            "cloud.example.net": {"agent": "homelab", "target": 8080, "listen": 20001, "proxy": "caddy"},
            "git.example.net": {"agent": "NAS", "target": 3000, "listen": 20002, "proxy": "caddy",
                                "allow_from": ["203.0.113.0/24"]},
        }

        def shown(*args):
            words, agents = rift_site.parse_list_args(args)
            return sorted(h for h, s in sites.items() if rift_site.site_matches(h, s, words, agents))

        self.assertEqual(shown(), ["cloud.example.net", "git.example.net"])
        self.assertEqual(shown("git"), ["git.example.net"])
        self.assertEqual(shown("--agent", "nas"), ["git.example.net"])
        self.assertEqual(shown("--agent=homelab"), ["cloud.example.net"])
        self.assertEqual(shown("8080"), ["cloud.example.net"])
        self.assertEqual(shown("203.0.113", "caddy"), ["git.example.net"])
        self.assertEqual(shown("example", "--agent", "core"), [])
        with self.assertRaises(rift_site.SiteError):
            rift_site.parse_list_args(["--sort"])
        with self.assertRaises(rift_site.SiteError):
            rift_site.parse_list_args(["--agent"])

