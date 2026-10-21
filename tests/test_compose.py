"""Controlli sulla configurazione di Docker Compose e del Dockerfile.

Riferimenti: threat model I-04 (porte esposte per errore) ed E-02
(isolamento del fetcher); ASVS v5.0.0 capitolo V13.
"""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[1]
COMPOSE = yaml.safe_load((ROOT / "compose.yaml").read_text())
SERVICES = COMPOSE["services"]
PYTHON_SERVICES = ["backend", "worker", "fetcher"]


def _published(service: dict) -> list[str]:
    return [str(p) for p in service.get("ports", [])]


def test_compose_no_exposed_ports():
    """Database e Redis non pubblicano porte; gli altri servizi solo su 127.0.0.1."""
    for name in ("db", "redis"):
        assert not _published(SERVICES[name]), f"{name} non deve pubblicare porte"
    for name, service in SERVICES.items():
        for port in _published(service):
            assert port.startswith("127.0.0.1:"), f"{name}: porta {port} non legata a 127.0.0.1"


@pytest.mark.parametrize("network", ["data", "fetch"])
def test_internal_networks(network):
    assert COMPOSE["networks"][network].get("internal") is True


def test_fetcher_cannot_reach_data_network():
    assert "data" not in SERVICES["fetcher"]["networks"]


@pytest.mark.parametrize("name", PYTHON_SERVICES)
def test_python_services_hardened(name):
    service = SERVICES[name]
    assert service.get("read_only") is True
    assert service.get("cap_drop") == ["ALL"]
    assert "no-new-privileges:true" in service.get("security_opt", [])


def test_dockerfile_runs_as_non_root():
    lines = (ROOT / "Dockerfile").read_text().splitlines()
    last_user = [line for line in lines if line.startswith("USER ")][-1]
    assert last_user.split()[1].split(":")[0] not in {"0", "root"}
