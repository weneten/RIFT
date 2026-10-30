import importlib.machinery
import importlib.util
import json
import unittest
from pathlib import Path

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
        with self.assertRaises(rift_site.SiteError):
            rift_site.resolve_public_ip("", "")
        with self.assertRaises(rift_site.SiteError):
            rift_site.resolve_public_ip("", "rift.example.net")
        with self.assertRaises(rift_site.SiteError):
            rift_site.resolve_public_ip("", "198.51.100.10,203.0.113.10")

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
        ]
        agents = [{"id": "a1", "name": "heim"}]
        sites = {"beszel.example.net": {"forward_id": 1, "proxy": "traefik"}}
        rows = rift_site.forward_rows(forwards, agents, sites)
        self.assertEqual(rows[0][-1], "SITE")
        self.assertEqual(
            rows[1],
            ("1", "heim", "TCP", "10.0.0.207:20000", "8091", "v4", "local", "transparent", "enabled",
             "beszel.example.net (traefik)"),
        )
        self.assertEqual(rows[2][3], "[2001:db8::1]:1337-1339")
        self.assertEqual(rows[2][8:], ("disabled", ""))

    def test_add_arguments_and_the_proxy_option(self):
        self.assertEqual(
            rift_site.parse_add_args(["core", "a.example", "8081", "--proxy", "traefik"]),
            (["core", "a.example", "8081"], "traefik"),
        )
        self.assertEqual(
            rift_site.parse_add_args(["--proxy=caddy", "core", "a.example", "8081"]),
            (["core", "a.example", "8081"], "caddy"),
        )
        self.assertEqual(rift_site.parse_add_args(["core", "a.example", "8081"])[1], None)
        with self.assertRaises(rift_site.SiteError) as typo:
            rift_site.parse_add_args(["core", "a.example", "8081", "--proxy-traefik"])
        self.assertIn("use --proxy traefik (with a space)", str(typo.exception))
        for bad in (["core", "a.example", "8081", "--proxy"], ["core", "a.example"], ["a", "b", "1", "--x"]):
            with self.assertRaises(rift_site.SiteError):
                rift_site.parse_add_args(bad)

    def test_messages_name_the_command_not_the_file(self):
        self.assertIn("usage: rift site add", rift_site.usage())
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


if __name__ == "__main__":
    unittest.main()
