"""Autorizzazione verificata su tutte le route (ASVS 8.1.1, 8.2.1, 8.2.3, 8.3.1;
threat model I-02, E-04, AC11). Una route nuova senza livello d'accesso, senza
protezione, non documentata o con campi interni nella risposta fa fallire la CI."""

import re
import uuid
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.routing import APIRoute
from phishlens_backend.authz import (
    FORBIDDEN_RESPONSE_FIELDS,
    ROUTE_POLICY,
    Access,
    owned_or_404,
)
from phishlens_backend.main import create_app
from phishlens_backend.sessions import any_session, full_session, partial_session
from phishlens_db.engine import make_engine
from phishlens_db.models import User, UserSession
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

DEPENDENCY_FOR = {
    Access.FULL: full_session,
    Access.PARTIAL: partial_session,
    Access.ANY: any_session,
}
SESSION_DEPENDENCIES = set(DEPENDENCY_FOR.values())
GOOD_PASSWORD = "cavallo batteria graffetta corretta"
AUTHORIZATION_DOC = Path(__file__).parents[2] / "docs" / "authorization.md"


@pytest.fixture
def app(settings, svc):
    return create_app(settings, svc)


def _walk(routes):
    """Route reali, anche dentro i router inclusi. Da FastAPI 0.157 app.routes contiene
    contenitori per i router inclusi: senza questa discesa i test passerebbero a vuoto."""
    for route in routes:
        if isinstance(route, APIRoute):
            yield route
        elif hasattr(route, "original_router"):
            yield from _walk(route.original_router.routes)


def api_routes(app):
    for route in _walk(app.routes):
        for method in route.methods - {"HEAD"}:
            yield method, route.path, route


def test_route_discovery_matches_openapi(app):
    """Controllo dei controlli: la lista usata dai test coincide con quella pubblica
    di OpenAPI. Se FastAPI cambia di nuovo struttura, questo test fallisce."""
    walked = {(m, p) for m, p, _ in api_routes(app)}
    published = {(m.upper(), p) for p, ops in app.openapi()["paths"].items() for m in ops}
    assert walked == published
    assert len(walked) >= 10


def session_dependencies(dependant) -> set:
    found = set()
    for dep in dependant.dependencies:
        if dep.call in SESSION_DEPENDENCIES:
            found.add(dep.call)
        found |= session_dependencies(dep)
    return found


def test_every_route_has_a_declared_policy(app):
    routes = {(m, p) for m, p, _ in api_routes(app)}
    assert routes - set(ROUTE_POLICY) == set(), "route senza livello d'accesso in authz.py"
    assert set(ROUTE_POLICY) - routes == set(), "livello dichiarato per una route inesistente"


def test_policy_matches_the_dependency_in_code(app):
    for method, path, route in api_routes(app):
        deps = session_dependencies(route.dependant)
        expected = ROUTE_POLICY[(method, path)]
        if expected is Access.PUBLIC:
            assert deps == set(), f"{method} {path} è pubblica ma usa una sessione"
        else:
            assert deps == {DEPENDENCY_FOR[expected]}, f"{method} {path}: protezione diversa"


def _url(path: str) -> str:
    return re.sub(r"\{[^}]+\}", str(uuid.uuid4()), path)


def test_protected_routes_reject_anonymous_requests(client, app):
    for method, path, _ in api_routes(app):
        if ROUTE_POLICY[(method, path)] is not Access.PUBLIC:
            r = client.request(method, _url(path), json={})
            assert r.status_code == 401, f"{method} {path} risponde {r.status_code} senza sessione"


def test_full_routes_reject_partial_session(client, enroll, app):
    """Il caso realistico: l'attaccante conosce la password ma non ha il secondo fattore."""
    email = f"meta-{uuid.uuid4().hex[:8]}@example.com"
    enroll(client, email)
    client.cookies.clear()
    r = client.post("/auth/login", json={"email": email, "password": GOOD_PASSWORD})
    assert r.status_code == 200
    for method, path, _ in api_routes(app):
        if ROUTE_POLICY[(method, path)] is Access.FULL:
            r = client.request(method, _url(path), json={})
            assert r.status_code == 401, f"{method} {path} accetta una sessione parziale"


def test_owned_or_404_hides_other_users_objects(make_client, enroll, database):
    """IDOR (ASVS 8.2.2, AC11): un oggetto altrui è indistinguibile da uno inesistente.
    Le route con un ID nel percorso (analisi, passo 3.6) usano tutte questa funzione."""
    a_email, b_email = (f"{n}-{uuid.uuid4().hex[:8]}@example.com" for n in ("alice", "bob"))
    enroll(make_client(), a_email)
    enroll(make_client(), b_email)
    engine = make_engine(database["app"])
    with Session(engine) as db:
        alice = db.scalar(select(User).where(User.email == a_email))
        bob = db.scalar(select(User).where(User.email == b_email))
        session = db.scalar(select(UserSession).where(UserSession.user_id == alice.id))
        assert owned_or_404(db, UserSession, session.id, alice.id, "user_id") == session
        for owner, object_id in ((bob.id, session.id), (alice.id, uuid.uuid4())):
            with pytest.raises(HTTPException) as exc:
                owned_or_404(db, UserSession, object_id, owner, "user_id")
            assert exc.value.status_code == 404
            assert exc.value.detail == "Non trovato."
    engine.dispose()


def test_every_request_body_forbids_unknown_fields(app):
    for method, path, route in api_routes(app):
        body = route.dependant.body_params
        for field in body:
            model = field.field_info.annotation
            if isinstance(model, type) and issubclass(model, BaseModel):
                assert model.model_config.get("extra") == "forbid", f"{method} {path}"


def _schema_properties(schema: dict, components: dict, seen=None) -> set[str]:
    seen = seen if seen is not None else set()
    names = set(schema.get("properties", {}))
    refs = re.findall(r'"\$ref": "#/components/schemas/([^"]+)"', str(schema).replace("'", '"'))
    for ref in refs:
        if ref not in seen:
            seen.add(ref)
            names |= _schema_properties(components[ref], components, seen)
    for prop in schema.get("properties", {}).values():
        names |= _schema_properties(prop, components, seen)
    if "items" in schema:
        names |= _schema_properties(schema["items"], components, seen)
    return names


def test_responses_never_expose_internal_fields(app):
    spec = app.openapi()
    components = spec.get("components", {}).get("schemas", {})
    for path, methods in spec["paths"].items():
        for method, op in methods.items():
            for code, resp in op.get("responses", {}).items():
                schema = resp.get("content", {}).get("application/json", {}).get("schema", {})
                exposed = _schema_properties(schema, components) & FORBIDDEN_RESPONSE_FIELDS
                assert not exposed, f"{method.upper()} {path} ({code}) espone {exposed}"


def test_every_route_has_a_response_model(app):
    for method, path, route in api_routes(app):
        assert route.response_model is not None, f"{method} {path} senza response_model"


def documented_routes() -> set[tuple[str, str]]:
    """Coppie (metodo, percorso) nella prima colonna della tabella di authorization.md.
    In una cella come `POST /a`, `/b` il metodo vale anche per i percorsi successivi."""
    routes = set()
    for line in AUTHORIZATION_DOC.read_text(encoding="utf-8").splitlines():
        if not line.startswith("| `"):
            continue
        method = None
        for token in re.findall(r"`([^`]+)`", line.split("|")[1]):
            m = re.fullmatch(r"(?:(GET|POST|PUT|PATCH|DELETE) )?(/\S*)", token.strip())
            if m:
                method = m.group(1) or method
                routes.add((method, re.sub(r"\{[^}]+\}", "{}", m.group(2))))
    return routes


def test_every_route_is_documented(app):
    documented = documented_routes()
    missing = sorted(
        f"{m} {p}"
        for m, p, _ in api_routes(app)
        if (m, re.sub(r"\{[^}]+\}", "{}", p)) not in documented
    )
    assert not missing, f"route non presenti in docs/authorization.md: {missing}"
