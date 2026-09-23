from app.main import app, health
from app.security import (
    client_secret,
    generate_proxy_secret,
    proxy_links,
    validate_secret,
    validate_slug,
    validate_tag,
)


def test_secret_generation_and_padding():
    secret = generate_proxy_secret()
    assert validate_secret(secret)
    assert len(secret) == 32
    assert client_secret(secret, True) == "dd" + secret
    assert client_secret(secret, False) == secret


def test_tag_validation():
    assert validate_tag("a" * 32)
    assert not validate_tag("z" * 32)
    assert not validate_tag("a" * 31)


def test_slug_validation():
    assert validate_slug("de-premium-01")
    assert not validate_slug("DE Premium")


def test_proxy_links():
    links = proxy_links("proxy.example.com", 443, "a" * 32, True)
    assert links["tg"].startswith("tg://proxy?")
    assert "proxy.example.com" in links["https"]
    assert "dd" + ("a" * 32) in links["https"]


def test_application_import_and_routes():
    assert app.title
    paths = {route.path for route in app.routes}
    assert "/health" in paths
    assert "/login" in paths
    assert "/servers" in paths
    assert "/proxies" in paths
    assert "/sponsors" in paths
    assert "/proxies/{proxy_id}" in paths
    assert "/proxies/{proxy_id}/update" in paths
    assert "/proxies/{proxy_id}/rotate-secret" in paths
    assert "/proxies/{proxy_id}/actions/{action}" in paths
    assert "/servers/{server_id}/diagnostics" in paths
    assert health()["ok"] is True
