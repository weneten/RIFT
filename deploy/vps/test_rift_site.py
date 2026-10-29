import importlib.machinery
import importlib.util
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

    def test_env_file_parsing(self):
        values = rift_site.parse_env_file(
            '# c\nRIFT_NPM_EMAIL="a@example.net"\nRIFT_NPM_PASSWORD=pw=1\n\nbad\n'
        )
        self.assertEqual(values, {"RIFT_NPM_EMAIL": "a@example.net", "RIFT_NPM_PASSWORD": "pw=1"})


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
