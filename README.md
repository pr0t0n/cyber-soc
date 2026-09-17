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

### Visibilidade em tempo real do agente

Antes, o evento ficava em `pending` sem nenhum sinal até o grafo inteiro
terminar (até ~900s no pior caso) — parecia uma caixa-preta. Cada nó do grafo
agora reporta o próprio veredito assim que termina
(`app/services/rules_engine.py:_persist_progress`), então `rules_engine_status`
passa por um estágio intermediário real, `analyzing`, com
`rules_engine_verdict.groups` sendo preenchido grupo a grupo:

```
pending -> analyzing (1/3 grupos) -> analyzing (2/3) -> analyzing (3/3) -> matched | no_match
```

Isso alimenta duas telas que antes eram estáticas:

- **Eventos**: cada linha é expansível (clique na linha) e mostra a
  **trilha do agente** — os 3 grupos + Supervisor com status ao vivo
  (⚪ aguardando / ⏳ rodando / ✅ concluído), o motivo que cada grupo deu, a
  reputação real de threat intel do IP de origem (Shodan/AbuseIPDB) e o evento
  bruto original. A lista também re-consulta a API a cada poucos segundos
  sozinha — sem precisar dar F5.
- **Dashboard**: card "Atividade do Agente" — feed dos últimos eventos com o
  estágio atual do Supervisor, que também atualiza sozinho. Cada linha (e cada
  incidente no card "Incidentes") linka para o evento de origem em Eventos,
  já expandido na trilha do agente.

### Análise em tempo real de verdade: triagem, concorrência e recuperação

Três problemas reais apareceram quando o agente nativo começou a gerar
tráfego de verdade (uma rajada de ~60 eventos do primeiro scan SCA):

1. **Ruído de compliance competindo com eventos de segurança**: um scan SCA
   gera dezenas de "eventos" (achados de auditoria de configuração, não
   comportamento malicioso) de uma vez, cada um competindo pelo mesmo worker
   de LLM que uma tentativa de brute force real precisava. Eventos cujas
   `rule.groups` do Wazuh são só `sca`/`rootcheck` agora tomam uma **via
   rápida** (`app/services/event_triage.py`): veredito determinístico,
   nenhuma chamada de IA, quase instantâneo. Status vira `informational`
   (nunca `no_match`, que implicaria uma análise de IA que não aconteceu).
2. **Contenção derrubando a responsividade de tudo, não só a análise**:
   disparar dezenas de eventos ao mesmo tempo contra um Ollama de CPU único
   não paraleliza — só faz o processo da API competir por memória/conexões
   (observado: até o `/api/auth/login` travava). Um semáforo
   (`_ANALYSIS_CONCURRENCY` em `app/services/rules_engine.py`) limita a 2 o
   número de eventos realmente em análise de IA ao mesmo tempo; o resto
   enfileira em vez de competir.
3. **Restart perdia o backlog silenciosamente**: `BackgroundTasks` do FastAPI
   só existe na memória do processo que agendou — um `docker compose up
   --build` no meio do processamento perdia todo evento `pending`/`analyzing`
   para sempre, sem aviso. `bootstrap()` agora reagenda qualquer evento nesse
   estado ao subir (`_requeue_stuck_events`).

### Um rótulo da fonte não é uma confirmação

Problema real observado: um evento chegava com `type: "SSHD brute force"` e
severidade "crítica" (herdada do `rule.level` do Wazuh), mas sem nenhuma
contagem de tentativas e sem nenhuma skill corroborando — o motor de regras
dizia "sem correspondência" enquanto a tela ainda destacava "brute force" e
"crítico" como se fossem fatos confirmados. Três correções:

1. **`Event.hit_count`**: extraído de `rule.firedtimes`/`rule.frequency`
   (Wazuh) quando disponível — sem contagem real, o campo fica `null` e a UI
   diz isso explicitamente ("sem contagem de tentativas"), em vez de deixar o
   rótulo sem contexto.
2. **`Event.rule_ref`**: guarda a regra de origem que gerou a severidade (ex.:
   `"Wazuh regra 5720, nível 12: SSHD brute force"`) — a severidade é um
   julgamento da FONTE, não do Cyber SOC, e agora isso fica explícito na tela
   em vez de só uma cor.
3. **Correspondência exata de técnica + veredito honesto sobre degradação**:
   se a fonte já tagueia o evento com uma técnica MITRE (`event.mitre`) que
   bate com o `external_id` de uma skill real do catálogo, isso vira
   correspondência confirmada independente do julgamento do LLM local
   (`qwen2.5:1.5b`, pequeno, ocasionalmente falha/degrada sob contenção de
   CPU) — ver `_exact_id_matches` em `app/agents/graph.py`. Cada veredito de
   grupo também carrega `degraded: bool`: quando o RAG ou a IA não completou
   uma avaliação real, o Supervisor não diz mais "nenhuma ação necessária"
   (uma afirmação forte) — diz "inconclusivo, revisar manualmente".

## Métricas reais de eficiência/velocidade/SLA

`GET /api/dashboard/analysis-metrics` (card "Eficiência do Motor de Regras"
no Dashboard) — nunca estimado, sempre calculado de timestamps reais de
banco (`Event.received_at`/`analyzed_at`, `Incident.created_at`):

- **Eficiência (%)**: entre as análises de IA concluídas (`matched`/
  `no_match`), quantas não tiveram nenhum grupo `degraded` — ou seja,
  quantas foram uma avaliação real de ponta a ponta, não uma degradação
  disfarçada de veredito.
- **Velocidade de análise**: mediana/p95 de `analyzed_at - received_at`
  entre os eventos que passaram pela IA (a via rápida de compliance não
  entra nessa conta — é medida à parte, "Via rápida").
- **SLA evento → incidente**: mediana/p95 de `Incident.created_at -
  Event.received_at` — quanto tempo realmente leva do evento chegar até um
  incidente ser aberto.
- **Fila (backlog)**: quantos eventos ainda estão `pending`/`analyzing`
  agora, e há quanto tempo o mais antigo deles está esperando.

## Raw (Wazuh/SIEM): dado bruto sem interpretação da IA

`GET /api/events/raw` (página "Raw (Wazuh)" no menu) — lista o payload
original que a fonte mandou (`Event.raw`), com busca textual livre e filtro
por fonte, sem nenhuma camada de veredito de IA — para quando o analista
precisa ver exatamente o que o SIEM relatou, não a interpretação do motor de
regras sobre isso.

## Threat intel real: Shodan + AbuseIPDB

Cadastrados como conectores `kind=threatintel` em Administração → Integrações
(`type=shodan` / `type=abuseipdb`, com a `api_key` real), testados via
"Testar credencial" na própria tela. A partir daí, todo evento com IP de
origem público passa a ser enriquecido de verdade na ingestão
(`app/services/threat_intel.py:analyze_traffic`) — reputação, portas
expostas, CVEs, nó Tor — e isso entra na nota de risco (`risk_score`), na
trilha do agente (Eventos) e no contexto do Copilot quando a pergunta cita um
IP (ex.: "o que é o IP 185.220.101.8?").

Bug corrigido nesta fase: `IocCache` (cache de reputação/geo) tinha
unicidade só em `indicator`, então o cache de geolocalização de um IP
"vazava" como se fosse cache (vazio) de threat intel para o mesmo IP —
Shodan/AbuseIPDB nunca eram chamados de verdade para um IP que já tinha
passado pelo world map. A chave agora é `(indicator, indicator_type)`.

## Página Regras: skills reais em YAML

Abaixo do Copilot no menu — catálogo real baixado de 6 fontes públicas + 1
fonte interna (ver `app/services/skills_catalog.py` e
`scripts/fetch_skills.py`), servido como YAML (`GET /api/skills/{id}`) e é a
mesma base usada pelo RAG acima:

| Fonte | O que é | Como foi obtido |
|-------|---------|------------------|
| **attack** | Técnicas MITRE ATT&CK Enterprise (nível superior) | STIX bundle oficial (`mitre-attack/attack-stix-data`) |
| **d3fend** | Contramedidas MITRE D3FEND, 6 táticas reais (Harden/Detect/Isolate/Deceive/Evict/Model) | Ontologia oficial `d3fend.json`, reconstruída via `rdfs:subClassOf`/`d3f:enables` |
| **suricata** | Assinaturas de rede reais (sid/msg/classtype) | Emerging Threats Open Ruleset |
| **modsecurity** | Regras de WAF reais (XSS/SQLi/RCE) | OWASP Core Rule Set (`coreruleset/coreruleset`) |
| **sigma** | Regras de detecção Sigma reais (amostra por categoria: windows/cloud/linux/network/web/...) + regras "zero-day" recentes | SigmaHQ/sigma oficial + abdulmyid-cyber/SIEM-Content |
| **agent_threats** | Regras reais de ameaça a agentes de IA (prompt injection, tool poisoning, data poisoning, ...), com referências a OWASP LLM/Agentic e MITRE ATLAS | Agent-Threat-Rule/agent-threat-rules (MIT) |
| **correlation** | **Não é externa** — regras de correlação autorais desta plataforma (`app/skills_data/correlation.json`): um rótulo de "brute force"/"port scan"/"ataque web" da fonte só vira correspondência confirmada com evidência real (contagem de tentativas OU reputação de IP já confirmada) | Escrita internamente, rotulada como tal (nunca disfarçada de feed externo) |

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

## Wazuh real em Docker (SIEM de origem)

`wazuh/` é um clone do stack oficial `wazuh/wazuh-docker` (single-node,
v4.14.7 — manager + indexer OpenSearch + dashboard), com uma integração
customizada que encaminha alertas para o Cyber SOC Copilot:

```bash
cd wazuh
docker compose -f generate-indexer-certs.yml run --rm generator  # gera config/wazuh_indexer_ssl_certs/ (fora do git — chaves privadas)
cp config/wazuh_cluster/wazuh_manager.conf.example config/wazuh_cluster/wazuh_manager.conf
# edite o <api_key> do bloco <integration> com o ingest_token real
# (POST /api/admin/connectors no Cyber SOC — devolvido em claro só na criação)
docker compose up -d
```

- **Manager**: API em `https://localhost:55000` (`wazuh-wui` /
  `MyS3cr37P450r.*-`), agente de registro em `1515`, eventos em `1514`.
- **Dashboard**: `https://localhost:8443` (`admin` / `SecretPassword`).
- **Integração customizada** (`config/integrations/custom-cyber-soc`,
  registrada em `config/wazuh_cluster/wazuh_manager.conf`): a cada alerta
  (nível ≥3), o manager executa esse script, que faz `POST` para
  `http://host.docker.internal:8020/api/ingest/wazuh` com o `Bearer` do
  conector "Wazuh Docker (local)" cadastrado em Administração → Integrações
  do Cyber SOC. **Atenção**: o script precisa de permissão `750`
  (`root:wazuh`, sem acesso de "outros") — é assim que os scripts oficiais
  (`slack`, `virustotal`, ...) vêm; com `755` o `wazuh-integratord` recusa
  executar (`wpopenv(): file ... has write permissions`).
- **Tráfego de rede local**: um agente Wazuh real (`wazuh.agent`, serviço
  `cyber-soc-local-net`) se registra automaticamente no manager (`authd`) e
  roda o módulo `syscollector` (`network: yes`, já habilitado por padrão) —
  reporta as interfaces de rede e contadores de tráfego reais do ambiente
  Docker (`GET /syscollector/{agent_id}/netiface` na API do Wazuh).
- Todo evento que chega por essa integração recebe a tag `LOCAL-WAZUH`
  (herdada do conector) e passa pelo mesmo motor de regras (skills + RAG +
  Supervisor) descrito acima — visível em Eventos/Dashboard filtrando por
  essa tag.
- **Logs reais da máquina do usuário** (`config/wazuh_agent/ossec.conf`): o
  agente monta, **read-only**, `~/Library/Logs` (`/host-mac-logs`) e
  `~/.zsh_history` (`/host-mac-history/.zsh_history`) — arquivos reais do
  macOS do usuário, via `${HOME}` no `docker-compose.yml`. O `localfile` lê o
  conteúdo (`wazuh-logcollector`, confirmado monitorando arquivos reais como
  `Claude/*.log`) e o `syscheck` (`realtime="yes"`) detecta mudanças nesses
  arquivos quase em tempo real. **Limitação honesta**: isto NÃO é o log de
  autenticação/segurança nativo do macOS — o unified logging (`log show`/
  `log stream`) não é um arquivo texto acessível de dentro de um container
  Linux, e o Docker Desktop não expõe `/var/log` do host real (só caminhos
  dentro do diretório do usuário). Para eventos de autenticação/segurança do
  próprio SO (não só arquivos), a única forma real é um agente Wazuh nativo
  instalado no macOS (fora do Docker) — deliberadamente não feito sem
  confirmação explícita, por instalar software persistente com acesso a logs
  do sistema na máquina do usuário.

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
| Migrations (Alembic) | Hoje `Base.metadata.create_all()` só cria tabelas novas, nunca altera colunas em tabela já existente — mudança de schema em ambiente já semeado exige `ALTER TABLE` manual (ou recriar o volume, em dev) |
| Métricas de eventos antigos | `analyzed_at` só existe a partir de quando a coluna foi criada — eventos analisados antes disso não entram em `analysis-metrics` até serem reprocessados (não há backfill retroativo) |
| Cobertura do agente nativo macOS (ULS) | Hoje cobre `sudo`/`sshd`/`loginwindow`/`screensharingd` — ampliar a query conforme surgir necessidade de outros processos |
