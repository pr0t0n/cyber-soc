"""Dispatcher de notificação/ticket (app/services/notify.py) — o último passo
do fluxo principal: incidente confirmado -> Slack/Teams/Jira/GLPI, por
criticidade configurada em cada conector.

`dispatch_incident_notification` abre suas próprias sessões (achado real de
teste de carga: a versão antiga recebia a sessão do motor de regras e segurava
essa conexão aberta durante até 4 chamadas HTTP externas sequenciais, esgotando
o pool do Postgres numa rajada — ver comentário em notify.py) — por isso estes
testes persistem conector/incidente/evento no banco real de teste (SQLite,
`conftest.py`) em vez de simular a sessão."""
from datetime import datetime, timezone

import httpx

from app.db import SessionLocal
from app.models import Connector, Event, Incident, Skill
from app.services import notify

_NOW = datetime(2026, 6, 25, 12, 0, tzinfo=timezone.utc)


class _Recorder:
    def __init__(self):
        self.calls: list[tuple[str, str, dict]] = []

    def make_client(self, *, get_response=None, post_response=None, fail: bool = False, fail_if_url_contains: str | None = None):
        recorder = self

        def _should_fail(url: str) -> bool:
            return fail or (fail_if_url_contains is not None and fail_if_url_contains in url)

        class _FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def get(self, url, **kwargs):
                recorder.calls.append(("GET", url, kwargs))
                if _should_fail(url):
                    raise httpx.ConnectError("indisponível")
                return get_response

            async def post(self, url, **kwargs):
                recorder.calls.append(("POST", url, kwargs))
                if _should_fail(url):
                    raise httpx.ConnectError("indisponível")
                return post_response

        return _FakeClient()


class _Resp:
    def __init__(self, json_data=None):
        self._json = json_data or {}

    def json(self):
        return self._json


async def _add(obj):
    async with SessionLocal() as db:
        db.add(obj)
        await db.commit()
        await db.refresh(obj)
        return obj.id


async def _make_incident(severity="critica", event_id=None) -> int:
    return await _add(Incident(
        code="INC-0001", title="Teste", status="backlog", severity=severity, risk_score=80, tag=None, event_id=event_id,
    ))


async def test_slack_sends_text_message_for_matching_severity(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(notify.httpx, "AsyncClient", lambda *a, **k: rec.make_client(post_response=_Resp()))
    await _add(Connector(kind="notification", type="slack", status="enabled", name="Slack", config={
        "webhook_url": "https://hooks.slack.test/x", "severities": ["critica", "alta"],
    }))
    incident_id = await _make_incident("critica")

    await notify.dispatch_incident_notification(incident_id)
    assert rec.calls
    method, url, kwargs = rec.calls[0]
    assert method == "POST"
    assert url == "https://hooks.slack.test/x"
    assert "INC-0001" in kwargs["json"]["text"]


async def test_dispatch_skips_connector_with_non_matching_severity(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(notify.httpx, "AsyncClient", lambda *a, **k: rec.make_client(post_response=_Resp()))
    await _add(Connector(kind="notification", type="slack", status="enabled", name="Slack", config={
        "webhook_url": "https://hooks.slack.test/x", "severities": ["baixa"],
    }))
    incident_id = await _make_incident("critica")

    await notify.dispatch_incident_notification(incident_id)
    assert rec.calls == []


async def test_teams_sends_messagecard(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(notify.httpx, "AsyncClient", lambda *a, **k: rec.make_client(post_response=_Resp()))
    await _add(Connector(kind="notification", type="teams", status="enabled", name="Teams", config={
        "webhook_url": "https://teams.test/webhook", "severities": ["critica"],
    }))
    incident_id = await _make_incident("critica")

    await notify.dispatch_incident_notification(incident_id)
    method, url, kwargs = rec.calls[0]
    assert kwargs["json"]["@type"] == "MessageCard"
    assert "INC-0001" in kwargs["json"]["title"]


async def test_jira_creates_issue_with_basic_auth(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(notify.httpx, "AsyncClient", lambda *a, **k: rec.make_client(post_response=_Resp()))
    await _add(Connector(kind="notification", type="jira", status="enabled", name="Jira", config={
        "base_url": "https://jira.test", "email": "a@b.com", "api_token": "tok", "project_key": "SOC",
        "severities": ["critica"],
    }))
    incident_id = await _make_incident("critica")

    await notify.dispatch_incident_notification(incident_id)
    method, url, kwargs = rec.calls[0]
    assert url == "https://jira.test/rest/api/2/issue"
    assert kwargs["auth"] == ("a@b.com", "tok")
    assert kwargs["json"]["fields"]["project"]["key"] == "SOC"


async def test_glpi_creates_ticket_via_two_step_session(monkeypatch):
    rec = _Recorder()

    def _client_factory(*a, **k):
        return rec.make_client(get_response=_Resp({"session_token": "sess123"}), post_response=_Resp({"id": 15}))

    monkeypatch.setattr(notify.httpx, "AsyncClient", _client_factory)
    await _add(Connector(kind="notification", type="glpi", status="enabled", name="GLPI", config={
        "base_url": "https://glpi.test/apirest.php", "app_token": "app1", "user_token": "user1",
        "severities": ["critica"],
    }))
    incident_id = await _make_incident("critica")

    await notify.dispatch_incident_notification(incident_id)
    assert rec.calls[0][0] == "GET"
    assert rec.calls[0][1] == "https://glpi.test/apirest.php/initSession"
    assert rec.calls[1][0] == "POST"
    assert rec.calls[1][1] == "https://glpi.test/apirest.php/Ticket/"
    assert rec.calls[1][2]["headers"]["Session-Token"] == "sess123"
    # Pedido real: o status do incidente na plataforma tem que vir do GLPI,
    # não de uma lista suspensa local — pra isso precisamos saber qual
    # ticket rastrear. Gravado numa segunda sessão própria, após a chamada
    # HTTP retornar (ver comentário em notify.py) — confere lendo de novo.
    async with SessionLocal() as db:
        incident = await db.get(Incident, incident_id)
        assert incident.glpi_ticket_id == 15


async def test_ticket_body_includes_ip_mitre_and_recommendation_when_event_available(monkeypatch):
    # Um analista N1 precisa decidir a partir do próprio ticket, sem abrir a
    # plataforma antes — risco/status/tag sozinhos (comportamento antigo) não
    # bastam.
    rec = _Recorder()

    def _client_factory(*a, **k):
        return rec.make_client(get_response=_Resp({"session_token": "sess123"}), post_response=_Resp({"id": 15}))

    monkeypatch.setattr(notify.httpx, "AsyncClient", _client_factory)
    await _add(Connector(kind="notification", type="glpi", status="enabled", name="GLPI", config={
        "base_url": "https://glpi.test/apirest.php", "app_token": "app1", "user_token": "user1",
        "severities": ["critica"],
    }))
    event_id = await _add(Event(
        source="wazuh", type="Possible port scan", severity="critica",
        timestamp=_NOW, received_at=_NOW,
        src_ip="203.0.113.9", src_port="51515", dst_ip="10.0.0.5", dst_port="22", protocol="TCP",
        mitre=["T1595"], matched_skills=["9000001"], hit_count=40,
        recommendation="Bloquear origem e revisar firewall.",
    ))
    incident_id = await _make_incident("critica", event_id=event_id)

    await notify.dispatch_incident_notification(incident_id)
    content = rec.calls[1][2]["json"]["input"]["content"]
    assert "203.0.113.9:51515" in content
    assert "10.0.0.5:22" in content
    assert "T1595" in content and "Varredura Ativa" in content and "Reconhecimento" in content
    assert "9000001" in content
    assert "Bloquear origem" in content


async def test_ticket_body_includes_abuseipdb_and_shodan_hydration_when_present(monkeypatch):
    """Achado real: a hidratação de threat intel (AbuseIPDB/Shodan) já era
    calculada na ingestão (`Event.enrichment`) mas nunca aparecia no corpo do
    ticket — um analista via "risco alto" sem saber que era reputação de IP
    confirmada, não um palpite."""
    rec = _Recorder()

    def _client_factory(*a, **k):
        return rec.make_client(get_response=_Resp({"session_token": "sess123"}), post_response=_Resp({"id": 17}))

    monkeypatch.setattr(notify.httpx, "AsyncClient", _client_factory)
    await _add(Connector(kind="notification", type="glpi", status="enabled", name="GLPI", config={
        "base_url": "https://glpi.test/apirest.php", "app_token": "app1", "user_token": "user1",
        "severities": ["critica"],
    }))
    event_id = await _add(Event(
        source="wazuh", type="Possible port scan", severity="critica",
        timestamp=_NOW, received_at=_NOW,
        src_ip="203.0.113.9", dst_ip="10.0.0.5", protocol="TCP",
        mitre=[], matched_skills=[],
        enrichment={
            "abuseipdb": {
                "provider": "abuseipdb", "status": "ok", "abuse_confidence_score": 92,
                "total_reports": 340, "isp": "Bad Hosting LLC", "is_tor": True,
            },
            "shodan": {
                "provider": "shodan", "status": "ok", "found": True,
                "ports": [22, 2222], "org": "Bad Hosting LLC", "vulns": ["CVE-2021-1234"],
            },
            "assessment": {"reasons": ["AbuseIPDB: reputação maliciosa (92/100, 340 relatos)."]},
        },
    ))
    incident_id = await _make_incident("critica", event_id=event_id)

    await notify.dispatch_incident_notification(incident_id)
    content = rec.calls[1][2]["json"]["input"]["content"]
    assert "AbuseIPDB" in content and "92/100" in content and "340" in content and "Tor" in content
    assert "Shodan" in content and "22" in content and "2222" in content and "CVE-2021-1234" in content
    assert "Avaliação de risco do tráfego" in content


async def test_describe_skills_enriches_with_real_name_from_catalog():
    """"CSOC-002" sozinho não diz nada a um analista — busca o nome real na
    tabela `skills` (catálogo unificado, skills_catalog.py) em vez de
    mostrar só o ID cru."""
    async with SessionLocal() as db:
        db.add(Skill(
            source="attack_defend", external_id="CSOC-002", name="Varredura de portas de IP com reputação maliciosa confirmada",
            category="teste", yaml_content="skill: teste", search_text="teste",
        ))
        await db.commit()

        described = await notify._describe_skills(db, ["CSOC-002", "T1999-nao-catalogado"])
        assert described == [
            "CSOC-002 (Varredura de portas de IP com reputação maliciosa confirmada)",
            "T1999-nao-catalogado",
        ]


async def test_ticket_body_includes_geo_why_and_weekly_history(monkeypatch):
    rec = _Recorder()

    def _client_factory(*a, **k):
        return rec.make_client(get_response=_Resp({"session_token": "sess123"}), post_response=_Resp({"id": 16}))

    monkeypatch.setattr(notify.httpx, "AsyncClient", _client_factory)
    await _add(Connector(kind="notification", type="glpi", status="enabled", name="GLPI", config={
        "base_url": "https://glpi.test/apirest.php", "app_token": "app1", "user_token": "user1",
        "severities": ["critica"],
    }))
    event_id = await _add(Event(
        source="wazuh", type="Possible port scan", severity="critica",
        timestamp=_NOW, received_at=_NOW,
        src_ip="203.0.113.9", dst_ip="10.0.0.5", protocol="TCP",
        country="RU", city="Moscow", mitre=[], matched_skills=[],
        rules_engine_verdict={"summary": "Correspondência determinística confirmada: varredura de portas."},
    ))
    incident_id = await _make_incident("critica", event_id=event_id)

    await notify.dispatch_incident_notification(incident_id)
    content = rec.calls[1][2]["json"]["input"]["content"]
    assert "Moscow" in content and "RU" in content
    assert "Por que este alerta: Correspondência determinística confirmada" in content
    assert "NUNCA vista antes" in content  # nenhum outro evento desta origem no banco de teste


async def test_a_failing_integration_does_not_block_others(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(
        notify.httpx, "AsyncClient",
        lambda *a, **k: rec.make_client(post_response=_Resp(), fail_if_url_contains="broken"),
    )
    await _add(Connector(kind="notification", type="slack", status="enabled", name="Slack quebrado", config={
        "webhook_url": "https://hooks.slack.test/broken", "severities": ["critica"],
    }))
    await _add(Connector(kind="notification", type="slack", status="enabled", name="Slack ok", config={
        "webhook_url": "https://hooks.slack.test/ok", "severities": ["critica"],
    }))
    incident_id = await _make_incident("critica")

    await notify.dispatch_incident_notification(incident_id)
    # Ambos foram tentados (a falha do primeiro não interrompeu o loop) — a
    # prova de que "não bloqueia os outros" é o segundo ter sido alcançado.
    urls = [url for _, url, _ in rec.calls]
    assert urls == ["https://hooks.slack.test/broken", "https://hooks.slack.test/ok"]


async def test_dispatch_is_noop_for_unknown_incident_id():
    await notify.dispatch_incident_notification(999999)
