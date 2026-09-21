"""Esquema real de credenciais e formato de integração por (kind, type) de
conector — substitui o textarea de JSON livre (sem nenhuma orientação do que
cada plataforma realmente precisa) por campos nomeados, com texto de ajuda e
o formato exato de integração, extraído da documentação oficial de cada
plataforma (não inventado):

  - Wazuh: https://documentation.wazuh.com/current/user-manual/manager/manual-integration.html
    (formato do bloco <integration> — name/hook_url/api_key/alert_format) e
    https://documentation.wazuh.com/current/user-manual/api/getting-started.html
    (autenticação da API REST do manager — Basic Auth em
    /security/user/authenticate devolve um JWT).
  - Elasticsearch: https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-cluster-health
    (GET /_cluster/health, autenticação via ApiKey ou Basic Auth).
  - AbuseIPDB/Shodan: já têm teste real implementado (app/services/threat_intel.py),
    mantidos aqui só para o esquema de campos.

Onde a documentação de um provedor ainda não foi verificada aqui, o campo
`fields` reflete convenção pública conhecida da API, mas `test_supported` é
`False` — a plataforma não finge testar uma credencial que não sabe validar."""
from __future__ import annotations

from typing import Any

_TAG_FIELD = {
    "key": "client_tag", "label": "Tag do cliente", "type": "text", "required": False, "secret": False,
    "help": "Rotula os eventos ingeridos com este token (ex.: nome do cliente numa operação MSSP) — filtrável no dashboard.",
}

CONNECTOR_SCHEMAS: dict[tuple[str, str], dict[str, Any]] = {
    ("siem", "wazuh"): {
        "docs_url": "https://documentation.wazuh.com/current/user-manual/manager/manual-integration.html",
        "mode": "push",
        "integration_format": (
            "O Wazuh Manager EMPURRA os alertas para cá — não é a plataforma que puxa. "
            "No ossec.conf do manager, adicione (formato exigido pela documentação oficial: "
            "name precisa começar com 'custom-', alert_format precisa ser 'json'):\n\n"
            "<integration>\n"
            "  <name>custom-cyber-soc</name>\n"
            "  <hook_url>{ingest_url}</hook_url>\n"
            "  <api_key>{ingest_token}</api_key>\n"
            "  <alert_format>json</alert_format>\n"
            "</integration>\n\n"
            "E um script em /var/ossec/integrations/custom-cyber-soc que recebe "
            "(alert_file, api_key, hook_url) e repassa o alerta como POST JSON com "
            "header 'Authorization: Bearer <api_key>' — ver wazuh/config/integrations/."
        ),
        "fields": [
            _TAG_FIELD,
            {
                "key": "manager_url", "label": "URL da API do Manager (opcional)", "type": "text",
                "required": False, "secret": False,
                "help": "Ex.: https://wazuh.manager:55000 — usada só pelo botão Testar, para confirmar que o "
                        "manager está acessível e as credenciais da API REST são válidas. A ingestão em si "
                        "não depende disso (é push).",
            },
            {
                "key": "api_username", "label": "Usuário da API do Manager", "type": "text",
                "required": False, "secret": False, "help": "Padrão de fábrica do Wazuh: 'wazuh' (troque em produção).",
            },
            {
                "key": "api_password", "label": "Senha da API do Manager", "type": "password",
                "required": False, "secret": True, "help": "Autenticação HTTP Basic contra /security/user/authenticate.",
            },
        ],
        "test_supported": True,
    },
    ("siem", "elastic"): {
        "docs_url": "https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-cluster-health",
        "mode": "push",
        "integration_format": (
            "Aponte uma ação de webhook (Kibana Watcher, ou output HTTP do Logstash/"
            "Filebeat) do seu Elasticsearch para este endpoint, com header "
            "'Authorization: Bearer {ingest_token}'. Os documentos devem seguir campos "
            "estilo ECS (event.action, source.ip, destination.ip, event.severity, "
            "threat.technique.id) — é o que app/api/ingest.py espera para traduzir."
        ),
        "fields": [
            _TAG_FIELD,
            {
                "key": "es_url", "label": "URL do Elasticsearch (opcional)", "type": "text",
                "required": False, "secret": False,
                "help": "Ex.: https://elastic.exemplo:9200 — usada só pelo botão Testar (GET /_cluster/health).",
            },
            {
                "key": "api_key", "label": "API Key do Elasticsearch", "type": "password",
                "required": False, "secret": True,
                "help": "Enviada como 'Authorization: ApiKey <valor>' — gerada em Kibana Stack Management -> API keys.",
            },
        ],
        "test_supported": True,
    },
    ("siem", "generic"): {
        "docs_url": None,
        "mode": "push",
        "integration_format": (
            "Schema próprio desta plataforma (sem fonte externa) — POST JSON com "
            "header 'Authorization: Bearer {ingest_token}' para {ingest_url}, campos: "
            "type, severity, src_ip, dst_ip, src_port, dst_port, protocol, mitre "
            "(lista de IDs ATT&CK), behavior, hit_count, rule_ref."
        ),
        "fields": [_TAG_FIELD],
        "test_supported": False,
    },
    ("threatintel", "abuseipdb"): {
        "docs_url": "https://docs.abuseipdb.com/",
        "mode": "pull",
        "integration_format": "A plataforma consulta a API do AbuseIPDB (pull) ao enriquecer o IP de origem de um evento.",
        "fields": [{"key": "api_key", "label": "API Key", "type": "password", "required": True, "secret": True}],
        "test_supported": True,
    },
    ("threatintel", "shodan"): {
        "docs_url": "https://developer.shodan.io/api",
        "mode": "pull",
        "integration_format": "A plataforma consulta a API do Shodan (pull) ao enriquecer o IP de origem de um evento.",
        "fields": [{"key": "api_key", "label": "API Key", "type": "password", "required": True, "secret": True}],
        "test_supported": True,
    },
    ("threatintel", "virustotal"): {
        "docs_url": "https://docs.virustotal.com/reference/overview",
        "mode": "pull",
        "integration_format": "Header 'x-apikey: <api_key>' na API pública do VirusTotal.",
        "fields": [{"key": "api_key", "label": "API Key", "type": "password", "required": True, "secret": True}],
        "test_supported": False,
    },
    ("threatintel", "socradar"): {
        "docs_url": "https://platform.socradar.com/docs/",
        "mode": "pull",
        "integration_format": "Autenticação por API key própria do SOCRadar (varia por módulo contratado).",
        "fields": [{"key": "api_key", "label": "API Key", "type": "password", "required": True, "secret": True}],
        "test_supported": False,
    },
    ("notification", "slack"): {
        "docs_url": "https://api.slack.com/messaging/webhooks",
        "mode": "push",
        "integration_format": "A plataforma envia (push) para uma Incoming Webhook URL do Slack.",
        "fields": [{"key": "webhook_url", "label": "Webhook URL", "type": "text", "required": True, "secret": False}],
        "test_supported": False,
    },
    ("notification", "teams"): {
        "docs_url": "https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook",
        "mode": "push",
        "integration_format": (
            "A plataforma envia (push) para uma URL de Workflows webhook do Teams "
            "(fluxo 'Quando uma solicitação de webhook do Teams é recebida', via Power "
            "Automate) — os antigos conectores do Office 365 foram desativados em "
            "maio/2026; ainda aceita conteúdo não interativo no formato MessageCard."
        ),
        "fields": [{"key": "webhook_url", "label": "Webhook URL", "type": "text", "required": True, "secret": False}],
        "test_supported": False,
    },
    ("notification", "webhook"): {
        "docs_url": None,
        "mode": "push",
        "integration_format": "Webhook genérico — a plataforma faz POST JSON na URL configurada.",
        "fields": [
            {"key": "webhook_url", "label": "Webhook URL", "type": "text", "required": True, "secret": False},
            {"key": "secret", "label": "Segredo (opcional, HMAC do payload)", "type": "password", "required": False, "secret": True},
        ],
        "test_supported": False,
    },
    ("notification", "jira"): {
        "docs_url": "https://developer.atlassian.com/cloud/jira/platform/basic-auth-for-rest-apis/",
        "mode": "push",
        "integration_format": "API REST do Jira Cloud: Basic Auth com email + API token (não a senha da conta).",
        "fields": [
            {"key": "base_url", "label": "URL do Jira", "type": "text", "required": True, "secret": False},
            {"key": "email", "label": "E-mail da conta", "type": "text", "required": True, "secret": False},
            {"key": "api_token", "label": "API Token", "type": "password", "required": True, "secret": True},
            {
                "key": "project_key", "label": "Chave do projeto", "type": "text", "required": True, "secret": False,
                "help": "Ex.: SOC — chave do projeto Jira onde o chamado será aberto.",
            },
        ],
        "test_supported": False,
    },
    ("notification", "glpi"): {
        "docs_url": "https://github.com/glpi-project/glpi/blob/main/apirest.md",
        "mode": "push",
        "integration_format": "API REST do GLPI: App-Token (da aplicação) + User-Token (do usuário de serviço).",
        "fields": [
            {
                "key": "base_url", "label": "URL do GLPI", "type": "text", "required": True, "secret": False,
                "help": "Até o caminho da API, ex.: https://glpi.exemplo.com/apirest.php (sem barra final).",
            },
            {"key": "app_token", "label": "App-Token", "type": "password", "required": True, "secret": True},
            {"key": "user_token", "label": "User-Token", "type": "password", "required": True, "secret": True},
        ],
        "test_supported": True,
    },
    ("notification", "email"): {
        "docs_url": None,
        "mode": "push",
        "integration_format": "Envio via SMTP.",
        "fields": [
            {"key": "smtp_host", "label": "Host SMTP", "type": "text", "required": True, "secret": False},
            {"key": "smtp_port", "label": "Porta SMTP", "type": "text", "required": True, "secret": False},
            {"key": "username", "label": "Usuário", "type": "text", "required": False, "secret": False},
            {"key": "password", "label": "Senha", "type": "password", "required": False, "secret": True},
        ],
        "test_supported": False,
    },
}


def get_schema(kind: str, type_: str) -> dict[str, Any] | None:
    return CONNECTOR_SCHEMAS.get((kind, type_))


def render_integration_format(kind: str, type_: str, *, ingest_url: str | None, ingest_token: str | None) -> str | None:
    schema = get_schema(kind, type_)
    if not schema:
        return None
    text = schema["integration_format"]
    return text.format(ingest_url=ingest_url or "<indisponível>", ingest_token=ingest_token or "<gerado ao salvar>")
