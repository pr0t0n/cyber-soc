# Cyber SOC Copilot

Plataforma de IA especialista N1/N2 para o time de SOC/CSIRT: ingere eventos
(Wazuh/Elastic), classifica por **MITRE ATT&CK**, analisa **IP/porta/protocolo**
para uma nota de risco, e responde perguntas do analista via um **Copilot**
com LLM local.

Este é um projeto **novo e independente** — não reaproveita código de
`socless` nem `cyber-sdo` (dois outros SOC/security-orchestrators já existentes
neste workspace). Ver `AGENTS.md`.

## Arquitetura

```
frontend/   React + Vite + Tailwind (SPA)                       → :5173 (dev) / :80 (Caddy)
backend/    FastAPI (auth local JWT, ingestão, dashboard, chat)  → :8000
docker/     Dockerfiles (api multi-stage uv, frontend bun+Caddy) + Caddyfile
```

- **Auth local, não federada**: login e-mail/senha, sem autocadastro — contas
  só são criadas pelo admin (`POST /api/auth/users`). Ver `AGENTS.md` para o
  porquê disso ser intencional (spec explícita), diferente do SSO via HUB que
  `cyber-sdo` usa.
- **Sem dados mockados**: bootstrap cria só o admin inicial; eventos entram
  por ingestão.

## Subir com Docker

```bash
cp .env.example .env
docker compose up --build -d
docker compose exec ollama ollama pull qwen2.5:1.5b      # modelo de chat (Copilot + motor de regras)
docker compose exec ollama ollama pull nomic-embed-text  # modelo de embedding (RAG das skills)
```

- App: http://localhost:4300 (via Caddy, proxya `/api` para o backend)
- Dev direto: frontend em `bun run dev` (:5173) + API em :8000
- API/docs: http://localhost:8020/docs (porta host do compose; a rede interna usa :8000)
- **Login inicial (admin):** `admin@example.com` / `admin123`
  (definido via `BOOTSTRAP_ADMIN_EMAIL`/`BOOTSTRAP_ADMIN_PASSWORD` no `.env`)

Sem o modelo do Ollama baixado, o Copilot responde em modo degradado (mostra
o contexto bruto dos eventos em vez de gerar uma resposta). Isso também pode
acontecer com o modelo baixado, se a inferência (CPU) não responder dentro de
`LLM_TIMEOUT_SECONDS` — em uma máquina com muitos outros containers rodando,
uma resposta pode levar de alguns segundos a ~1-2 minutos; o Copilot nunca
inventa uma resposta quando isso acontece, apenas mostra o contexto bruto.

## Motor de regras: Supervisor LangGraph + MCP + RAG

Toda a análise de "isso é uma ameaça real?" roda como um grafo multi-agente
(`app/agents/graph.py`), disparado em **background** após cada ingestão (nunca
bloqueia o `POST /api/ingest` — Ollama em CPU pode levar dezenas de segundos
por chamada):

```text
START ──▶ TTP & Defesa (ATT&CK/D3FEND) ──▶ Assinaturas de Rede (Suricata)
      ──▶ Aplicação Web/WAF (ModSecurity) ──▶ Supervisor ──▶ END
```

- **Hidratação via RAG**: cada grupo consulta uma tool **MCP**
  (`app/mcp_server.py`, roda como subprocesso via stdio,
  `langchain-mcp-adapters`) que busca por **similaridade de embedding**
  (pgvector + `nomic-embed-text` via Ollama) as skills reais mais relevantes
  para o evento — nunca por substring.
- **3 grupos especialistas**, cada um com seu próprio prompt
  (`app/agents/prompts.py`): só decidem "casou" entre as candidatas que o RAG
  trouxe, nunca inventam uma skill fora da lista.
- **Supervisor**: dono da visão consolidada — agrega o veredito dos 3 grupos,
  decide o resultado final (`matched_skills`, resumo executivo) e é o que
  abre o Incidente quando `matched=true`.
- **Encadeado, não em paralelo**: os 3 grupos e o Supervisor rodam em
  sequência de propósito — todos compartilham o mesmo Ollama local (CPU, um
  único worker de inferência), e disparar as 3 chamadas ao mesmo tempo já
  derrubou o `llama-server` por memória em teste real. Cada nó continua um
  agente independente com seu próprio prompt/tool MCP; só a orquestração é
  sequencial, com retry automático por nó se o Ollama cair no meio.
- Sem resposta em JSON válido da IA (ou com o Ollama indisponível mesmo após
  retry), cada nó degrada para "não casou" (grupo) ou para a união
  determinística dos grupos (Supervisor) — nunca derruba a ingestão nem
  inventa um veredito.

`Event.rules_engine_status` vai de `pending` → `matched`/`no_match`; é esse
campo (não mais um limiar estático de risco/severidade) que alimenta o
estágio do meio do funil do dashboard e a abertura de Incidentes. O
Supervisor também escreve `Event.recommendation` — o próximo passo acionável
para o analista N1, citando a skill/contramedida que casou (ex.: a
contramedida D3FEND de uma técnica ATT&CK, ou a ação de contenção de uma
assinatura de rede/WAF) — visível na coluna "Motor de Regras" da tela Eventos.

## Página Regras: skills reais em YAML

Abaixo do Copilot no menu — catálogo real baixado de 6 fontes públicas (ver
`app/services/skills_catalog.py` e `scripts/fetch_skills.py`), servido como
YAML (`GET /api/skills/{id}`) e é a mesma base usada pelo RAG acima:

| Fonte | O que é | Como foi obtido |
|-------|---------|------------------|
| **attack** | Técnicas MITRE ATT&CK Enterprise (nível superior) | STIX bundle oficial (`mitre-attack/attack-stix-data`) |
| **d3fend** | Contramedidas MITRE D3FEND, 6 táticas reais (Harden/Detect/Isolate/Deceive/Evict/Model) | Ontologia oficial `d3fend.json`, reconstruída via `rdfs:subClassOf`/`d3f:enables` |
| **suricata** | Assinaturas de rede reais (sid/msg/classtype) | Emerging Threats Open Ruleset |
| **modsecurity** | Regras de WAF reais (XSS/SQLi/RCE) | OWASP Core Rule Set (`coreruleset/coreruleset`) |
| **sigma** | Regras de detecção Sigma reais (amostra por categoria: windows/cloud/linux/network/web/...) + regras "zero-day" recentes | SigmaHQ/sigma oficial + abdulmyid-cyber/SIEM-Content |
| **agent_threats** | Regras reais de ameaça a agentes de IA (prompt injection, tool poisoning, data poisoning, ...), com referências a OWASP LLM/Agentic e MITRE ATLAS | Agent-Threat-Rule/agent-threat-rules (MIT) |

`GET /api/skills/sources` mostra quantas skills de cada fonte já têm
embedding gerado (`hydration_pct`) — o backfill roda em background após o
startup (não atrasa o health check) e é resiliente ao Ollama ainda não estar
pronto.

Para atualizar o catálogo com dados mais recentes das mesmas fontes:
`GITHUB_TOKEN=<token com escopo repo> python scripts/fetch_skills.py`
(sem token, usa a credencial HTTPS do git já configurada na máquina, ou cai
no limite de 60 req/h sem autenticação da API do GitHub).

## Ingestão de eventos (agnóstica)

```bash
curl -X POST http://localhost:8020/api/ingest/wazuh -H 'Content-Type: application/json' -d '{
  "id":"1700000000.1","timestamp":"2026-06-25T14:23:00Z",
  "rule":{"level":12,"description":"SSHD brute force","mitre":{"id":["T1110"]}},
  "data":{"srcip":"185.220.101.8","dstip":"10.0.0.22","dstport":"3389","protocol":"TCP"}
}'
```

Fontes suportadas: `wazuh`, `elastic`, `generic` (`app/api/ingest.py`). Cada
evento é hidratado na chegada: reputação do IP (se um conector `abuseipdb`
estiver configurado em Integrações) + nota de risco por porta/protocolo
(`app/services/threat_intel.py`) — sempre calculada, mesmo sem provedor
externo.

## Testes

```bash
cd backend && uv sync --extra dev && uv run pytest -q
# ou, sem instalar nada no host:
docker compose --profile test run --rm test
```

## Escopo original (spec completa do usuário)

Especialista N1/N2 de SOC/CSIRT com MITRE ATT&CK/D3FEND, Snort/Suricata,
ModSecurity (WAF), integração Wazuh/Elastic; hidratação via Shodan, AbuseIPDB,
VirusTotal, SOCRadar; nota de risco por IP/porta/protocolo; ITSM (Jira/GLPI);
Google Meet/Teams/Slack para comunicação; dashboard com EPS, funil de
incidentes, heat map MITRE, status de chamados e das integrações; login local
sem autocadastro (admin cria usuários); chat sobre evento/incidente/risco/IP/
usuário; visual executivo, cores simples e minimalistas.

## O que já está implementado (MVP)

- Login local (JWT), sem autocadastro, admin cria/remove usuários.
- Ingestão Wazuh/Elastic/genérica → schema canônico com tags MITRE.
- Nota de risco por tráfego (porta/protocolo sempre; + AbuseIPDB/Shodan quando
  configurados) — `app/services/threat_intel.py`.
- **Ingestão protegida por fonte**: ao cadastrar um conector `kind=siem` (ex.:
  Wazuh), a API gera um `ingest_token` (devolvido em claro uma única vez, na
  criação) e passa a exigir `Authorization: Bearer <token>` em
  `POST /api/ingest/{esse tipo}`. Sem nenhum conector daquele tipo, a fonte
  segue aberta (modo dev).
- **Motor de regras de IA** (Supervisor LangGraph + MCP + RAG, ver seção
  acima): decide se o evento casa com uma skill real; quando casa, abre um
  Incidente com status **BackLog → Em Andamento → Concluído**
  (`app/models/incident.py`, `PATCH /api/incidents/{id}`) — distinto do
  "chamado" externo de ITSM.
- **Catálogo real de skills** (ATT&CK/D3FEND/Suricata/ModSecurity) em YAML na
  página Regras, hidratado por RAG (pgvector + Ollama embeddings).
- **Geolocalização real** do IP de origem (`app/services/geo.py`, via
  ipinfo.io — ip-api.com ficou fora por ser inacessível a partir desta rede)
  alimenta o world map do dashboard.
- **Tag de cliente por conector SIEM** (`config.client_tag`, ex.: `VALID`):
  todo evento ingerido com o token dessa integração herda a tag, e o
  dashboard tem um seletor para ver só aquele cliente
  (`?tag=VALID` em `/api/events` e em todos os endpoints de dashboard).
- Dashboard executivo (tema escuro): severidades, **funil EPS → Motor de
  Regras (IA) → Incidentes**, **heat map MITRE** (tática × técnica), **heat
  map de risco do ambiente** (dia × hora, 7 dias), **world map** com pinos
  por origem geográfica, status dos incidentes, status das integrações,
  chamados ITSM (estrutura pronta).
- Página de Integrações (SIEM/threat intel/notificação) com CRUD + teste de
  credencial ao vivo para AbuseIPDB/Shodan.
- Copilot: chat com contexto real dos eventos recentes via LLM local
  (Ollama), degrada honestamente sem inventar resposta se a IA não responder.

## Pendente (próximas fases)

| Item | Nota |
|------|------|
| VirusTotal, SOCRadar | AbuseIPDB e Shodan já têm query real; mesmo padrão de `threat_intel.py` se estende |
| Jira/GLPI (abertura de chamado real) | `connectors` já tem os tipos; falta o dispatcher de notificação/ticket |
| Slack/Teams/Google Meet | Mesma situação — tipos previstos no modelo, sem dispatcher ainda |
| RAG vetorial no Copilot | O motor de regras já usa RAG real; o chat do Copilot ainda usa lista simples dos últimos eventos |
| Catálogo de skills mais amplo | Suricata/ModSecurity hoje cobrem uma amostra real (scan completo + malware/exploit/XSS/SQLi/RCE parciais), não o ruleset inteiro |
| Registro no mfe-platform HUB | Deliberadamente adiado, como o `cyber-sdo` também fez |
