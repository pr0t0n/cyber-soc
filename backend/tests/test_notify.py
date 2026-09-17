"""Dispatcher de notificação/ticket (app/services/notify.py) — o último passo
do fluxo principal: incidente confirmado -> Slack/Teams/Jira/GLPI, por
criticidade configurada em cada conector."""
import httpx

from app.models import Connector, Incident
from app.services import notify


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


class _FakeScalars:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return _FakeScalars(self._rows)


class _FakeDB:
    def __init__(self, rows):
        self._rows = rows

    async def execute(self, *a, **k):
        return _FakeResult(self._rows)


def _incident(severity="critica") -> Incident:
    return Incident(id=1, code="INC-0001", title="Teste", status="backlog", severity=severity, risk_score=80, tag=None)


async def test_slack_sends_text_message_for_matching_severity(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(notify.httpx, "AsyncClient", lambda *a, **k: rec.make_client(post_response=_Resp()))
    connector = Connector(kind="notification", type="slack", status="enabled", name="Slack", config={
        "webhook_url": "https://hooks.slack.test/x", "severities": ["critica", "alta"],
    })

    await notify.dispatch_incident_notification(_FakeDB([connector]), _incident("critica"))
    assert rec.calls
    method, url, kwargs = rec.calls[0]
    assert method == "POST"
    assert url == "https://hooks.slack.test/x"
    assert "INC-0001" in kwargs["json"]["text"]


async def test_dispatch_skips_connector_with_non_matching_severity(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(notify.httpx, "AsyncClient", lambda *a, **k: rec.make_client(post_response=_Resp()))
    connector = Connector(kind="notification", type="slack", status="enabled", name="Slack", config={
        "webhook_url": "https://hooks.slack.test/x", "severities": ["baixa"],
    })

    await notify.dispatch_incident_notification(_FakeDB([connector]), _incident("critica"))
    assert rec.calls == []


async def test_teams_sends_messagecard(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(notify.httpx, "AsyncClient", lambda *a, **k: rec.make_client(post_response=_Resp()))
    connector = Connector(kind="notification", type="teams", status="enabled", name="Teams", config={
        "webhook_url": "https://teams.test/webhook", "severities": ["critica"],
    })

    await notify.dispatch_incident_notification(_FakeDB([connector]), _incident("critica"))
    method, url, kwargs = rec.calls[0]
    assert kwargs["json"]["@type"] == "MessageCard"
    assert "INC-0001" in kwargs["json"]["title"]


async def test_jira_creates_issue_with_basic_auth(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(notify.httpx, "AsyncClient", lambda *a, **k: rec.make_client(post_response=_Resp()))
    connector = Connector(kind="notification", type="jira", status="enabled", name="Jira", config={
        "base_url": "https://jira.test", "email": "a@b.com", "api_token": "tok", "project_key": "SOC",
        "severities": ["critica"],
    })

    await notify.dispatch_incident_notification(_FakeDB([connector]), _incident("critica"))
    method, url, kwargs = rec.calls[0]
    assert url == "https://jira.test/rest/api/2/issue"
    assert kwargs["auth"] == ("a@b.com", "tok")
    assert kwargs["json"]["fields"]["project"]["key"] == "SOC"


async def test_glpi_creates_ticket_via_two_step_session(monkeypatch):
    rec = _Recorder()

    def _client_factory(*a, **k):
        return rec.make_client(get_response=_Resp({"session_token": "sess123"}), post_response=_Resp({"id": 15}))

    monkeypatch.setattr(notify.httpx, "AsyncClient", _client_factory)
    connector = Connector(kind="notification", type="glpi", status="enabled", name="GLPI", config={
        "base_url": "https://glpi.test/apirest.php", "app_token": "app1", "user_token": "user1",
        "severities": ["critica"],
    })

    await notify.dispatch_incident_notification(_FakeDB([connector]), _incident("critica"))
    assert rec.calls[0][0] == "GET"
    assert rec.calls[0][1] == "https://glpi.test/apirest.php/initSession"
    assert rec.calls[1][0] == "POST"
    assert rec.calls[1][1] == "https://glpi.test/apirest.php/Ticket/"
    assert rec.calls[1][2]["headers"]["Session-Token"] == "sess123"


async def test_a_failing_integration_does_not_block_others(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(
        notify.httpx, "AsyncClient",
        lambda *a, **k: rec.make_client(post_response=_Resp(), fail_if_url_contains="broken"),
    )
    broken = Connector(kind="notification", type="slack", status="enabled", name="Slack quebrado", config={
        "webhook_url": "https://hooks.slack.test/broken", "severities": ["critica"],
    })
    working = Connector(kind="notification", type="slack", status="enabled", name="Slack ok", config={
        "webhook_url": "https://hooks.slack.test/ok", "severities": ["critica"],
    })

    await notify.dispatch_incident_notification(_FakeDB([broken, working]), _incident("critica"))
    # Ambos foram tentados (a falha do primeiro não interrompeu o loop) — a
    # prova de que "não bloqueia os outros" é o segundo ter sido alcançado.
    urls = [url for _, url, _ in rec.calls]
    assert urls == ["https://hooks.slack.test/broken", "https://hooks.slack.test/ok"]
