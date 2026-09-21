"""Orquestra o motor de regras (Supervisor LangGraph) em background após a
ingestão: nunca bloqueia o POST /api/ingest — Ollama em CPU pode levar dezenas
de segundos por chamada, e aqui rodam até 4 chamadas (3 grupos + supervisor).
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from sqlalchemy import select

from ..agents.graph import analyze_event
from ..db import SessionLocal, advisory_lock
from ..models import SEVERITIES, Event, Incident
from . import correlation, correlation_rules, learning, skill_signature_match
from .baseline import anomaly_reason, weekly_activity
from .correlation import count_recent_events_from_ip, find_open_incident_id
from .event_triage import (
    deterministic_verdict,
    fast_lane_verdict,
    is_compliance_noise,
    is_network_traffic,
    non_network_fast_lane_verdict,
)
from .notify import dispatch_incident_notification

# Limita quantos eventos passam pela análise de IA (LangGraph + Ollama) ao
# mesmo tempo. Ollama neste ambiente é um único worker de CPU — disparar
# dezenas de eventos de uma vez (ex.: rajada de SCA no primeiro scan de um
# agente novo, ou reprocessamento de backlog após um restart) não paraleliza
# de verdade, só faz o processo da API competir por memória/conexões e
# derruba a responsividade de tudo (login incluído, já observado). Isso
# enfileira: os eventos além do limite esperam a vez em vez de competir.
#
# Era 2 até este achado: medido ao vivo, 1 evento isolado (grafo completo —
# 3 grupos + supervisor) leva ~35s. Com só 2 EVENTOS concorrentes (o próprio
# limite anterior), cada um passou a levar 80-96s — mais que o dobro, e a
# soma (96s) já é maior que rodar os dois em SÉRIE teria sido (35x2=70s).
# Ollama de CPU único não entrega paralelismo real entre eventos (mesma
# razão pela qual os 3 grupos DENTRO de um evento já rodam em cadeia, não em
# paralelo — ver docstring do módulo, graph.py) — "2 concorrentes" só fazia
# os dois brigarem por CPU e saírem mais lentos, sem ganho de throughput
# nenhum. 1 é estritamente melhor aqui: cada evento na velocidade real do
# hardware, sem imposto de troca de contexto.
_ANALYSIS_CONCURRENCY = asyncio.Semaphore(1)

# Achado real de teste de carga: uma rajada de ingestão (centenas de eventos
# em segundos) agenda um `run_rules_engine_for_event` em background POR
# EVENTO imediatamente — mesmo os que vão cair no fast lane (poucos ms) fazem
# 2-4 idas ao Postgres cada (correlated_count, contexto de incidente aberto,
# aprendizado incremental) ANTES de sequer chegar no `_ANALYSIS_CONCURRENCY`
# acima, que só protege a chamada de LLM. Com centenas de tasks concorrentes
# fazendo isso ao mesmo tempo, o event loop único do processo da API fica
# ocupado o bastante para uma rota de leitura sem relação nenhuma (ex.:
# /api/dashboard/eps, só COUNT(*) indexado) demorar 30+ segundos para
# responder — validado com curl durante uma rajada de 250 eventos. Este
# segundo semáforo, mais largo, entra ANTES de qualquer acesso a banco (não
# só antes da IA) para conter o número de tasks concorrentes de verdade, sem
# apertar tanto quanto o limite da IA (que existe por causa da CPU do Ollama,
# um motivo diferente).
_INGEST_PROCESSING_CONCURRENCY = asyncio.Semaphore(12)




def _severity_rank(severity: str) -> int:
    """Menor índice = mais grave. Ingestão genérica aceita qualquer string de
    severidade vinda da fonte (não só as de `SEVERITIES`) — cai para "menos
    grave que tudo" em vez de derrubar a fusão de incidente por um valor
    inesperado."""
    return SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES)


def _escalate_risk_score(base_score: int, *, correlated_count: int | None, deterministic: bool) -> int:
    """Risk-Based Alerting: a nota de risco calculada no ingest (porta/
    protocolo/reputação de IP — app/services/threat_intel.py) ainda não sabe
    se a skill casou nem quantos eventos correlacionados a mesma origem já
    gerou. Um "PowerShell comum" e um "PowerShell com skill confirmada + 12
    eventos correlacionados da mesma origem" não podem carregar o mesmo risco
    só porque a porta é igual — ver seção 6 (Risk-Based Alerting) da análise
    de arquitetura. Bônus por confirmação objetiva (correlação determinística,
    sem opinião de LLM) pesa mais que confirmação via julgamento do modelo."""
    score = base_score + (15 if deterministic else 10)
    if correlated_count and correlated_count > 1:
        score += min((correlated_count - 1) * 2, 20)
    return min(100, score)


async def _open_incident_context(db, src_ip: str | None, *, before: datetime) -> str | None:
    """Retro-alimentação pedida: se esta origem já tem um incidente aberto,
    a análise do evento NOVO leva em conta o que a plataforma já confirmou
    sobre ele — não trata cada evento fundido como se a história começasse
    do zero a cada vez. É o Supervisor (LangGraph) recebendo o estado
    acumulado do incidente como contexto adicional (`_event_summary`,
    graph.py), não reavaliando um evento isolado sem memória do que já foi
    visto sobre a mesma origem."""
    existing_id = await find_open_incident_id(db, src_ip, before=before)
    if existing_id is None:
        return None
    incident = await db.get(Incident, existing_id)
    if incident is None:
        return None
    fused_rows = (await db.execute(
        select(Event.matched_skills, Event.mitre).where(Event.incident_id == existing_id)
    )).all()
    skills: set[str] = set()
    techniques: set[str] = set()
    for matched_skills, mitre in fused_rows:
        skills.update(matched_skills or [])
        techniques.update(mitre or [])
    created = incident.created_at
    if created and created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    before_aware = before if before.tzinfo else before.replace(tzinfo=timezone.utc)
    age_minutes = max(0, int((before_aware - created).total_seconds() // 60)) if created else None
    parts = [
        f"Esta origem já tem um incidente aberto ({incident.code}, severidade {incident.severity}, "
        f"aberto há {age_minutes} min, {len(fused_rows)} evento(s) já fundido(s) nele)."
    ]
    if techniques:
        parts.append(f"Técnica(s) MITRE já confirmada(s) neste incidente: {', '.join(sorted(techniques))}.")
    if skills:
        parts.append(f"Skill(s)/assinatura(s) já confirmada(s): {', '.join(sorted(skills))}.")
    return " ".join(parts)


async def _campaign_context(db, event: Event, *, before: datetime) -> str | None:
    """Segundo hop de correlação (L1->L2, análise de mercado seção 8.3):
    diferente de `_open_incident_context` (que só olha a MESMA origem
    dentro do MESMO incidente), isto olha PARA FORA — mesma técnica MITRE
    já confirmada em OUTRO incidente aberto de origem diferente, ou o mesmo
    destino sendo mirado por várias origens ao mesmo tempo. Nenhuma fonte
    de dado nova, só `Event`/`Incident` já existentes com uma pergunta
    diferente (`services/correlation.py`)."""
    parts = []
    matches = await correlation.find_technique_matches_in_other_open_incidents(
        db, event.mitre or [], exclude_src_ip=event.src_ip, before=before,
    )
    if matches:
        codes = sorted({code for code, _, _ in matches})
        techniques = sorted({t for _, _, t in matches})
        parts.append(
            f"Padrão de campanha: a(s) técnica(s) MITRE {', '.join(techniques)} deste evento já está(ão) "
            f"CONFIRMADA(S) em {len(codes)} outro(s) incidente(s) aberto(s) de origem diferente "
            f"({', '.join(codes)}) — não é uma origem isolada."
        )
    other_origins = await correlation.count_distinct_origins_targeting(
        db, event.dst_ip, exclude_src_ip=event.src_ip, before=before,
    )
    if other_origins:
        parts.append(
            f"Este mesmo destino ({event.dst_ip}) também está sendo alvo de {other_origins} outra(s) "
            f"origem(ns) distinta(s) nos últimos {correlation.MULTI_ORIGIN_TARGET_WINDOW_MINUTES} minutos "
            "— múltiplos atacantes mirando o mesmo ativo."
        )
    return " ".join(parts) if parts else None


async def _open_or_fuse_incident(db, event: Event) -> None:
    """Alert Fusion (seção 3 da análise de arquitetura): a mesma origem
    confirmada mais de uma vez na mesma janela de correlação (10 min) deve
    virar UM incidente que acumula evidência, não N incidentes duplicados que
    obrigam o analista a investigar a mesma origem várias vezes separadamente.

    Dispara notificação/ticket (`notify.py`) só na criação e quando o
    incidente de fato escala (risco ou severidade pioram) — nunca a cada
    evento fundido, ou um port scan com 50 eventos correlacionados viraria 50
    mensagens idênticas no Slack/Teams e 50 chamados duplicados. "Escalar" aqui
    é especificamente mudança de SEVERIDADE, não qualquer alta de risk_score —
    `correlated_count` sobe a cada evento fundido, então o bônus de correlação
    em `_escalate_risk_score` por si só faria o risco subir um pouco a cada
    fusão (ex.: 50 eventos de um port scan = 50 pequenas altas de risco), o
    que redispararia notificação a cada uma sem trazer sinal novo nenhum.

    `advisory_lock` (app/db.py) trava por origem ANTES do SELECT que decide
    criar-ou-fundir — achado real de teste de carga: sem isso, duas análises
    concorrentes da mesma origem, dentro da janela de correlação, podiam
    ambas ver "nenhum incidente aberto ainda" e cada uma criar o seu."""
    await advisory_lock(db, event.src_ip)
    existing_id = await find_open_incident_id(db, event.src_ip, before=event.received_at)
    if existing_id is not None:
        incident = await db.get(Incident, existing_id)
        event.incident_id = incident.id
        if event.risk_score > incident.risk_score:
            incident.risk_score = event.risk_score
        severity_escalated = _severity_rank(event.severity) < _severity_rank(incident.severity)
        if severity_escalated:
            incident.severity = event.severity
        await db.commit()
        if severity_escalated:
            await dispatch_incident_notification(incident.id)
        return

    # `code` deriva do `id` (autoincremento atômico do Postgres), não de um
    # `COUNT(*) + 1` calculado antes do insert — achado real de teste de
    # carga: duas análises concorrentes liam a mesma contagem e tentavam
    # criar o mesmo "INC-00NN", e a segunda falhava com violação de
    # unicidade (`incidents_code_key`). `id` nunca colide entre transações
    # concorrentes; o preço é que o código pode ter lacunas se um incidente
    # for excluído algum dia — aceitável, melhor que perder o incidente.
    incident = Incident(
        code=f"TMP-{event.id}",  # placeholder único (event.id já é PK) até o flush revelar o id do incidente
        title=f"{event.type} — {event.src_ip or 'origem desconhecida'}",
        status="backlog",
        severity=event.severity,
        risk_score=event.risk_score,
        tag=event.tag,
        event_id=event.id,
    )
    db.add(incident)
    await db.flush()
    incident.code = f"INC-{incident.id:04d}"
    event.incident_id = incident.id
    await db.commit()
    # `dispatch_incident_notification` abre e fecha suas PRÓPRIAS sessões —
    # nunca recebe `db` nem `incident` aqui, de propósito (achado real de
    # teste de carga grave: a versão antiga segurava esta MESMA conexão
    # aberta durante até 4 chamadas HTTP externas sequenciais, esgotando o
    # pool do Postgres numa rajada de incidentes — ver comentário em
    # notify.py). Isto já commitou tudo que precisava; nada aqui depende do
    # resultado da notificação.
    await dispatch_incident_notification(incident.id)


_STAGE_ORDER = ("attack_defend", "network_signature", "web_application")


async def _persist_progress(event_id: int, stage: str, group_verdict: dict) -> None:
    """Callback do grafo (app/agents/graph.py) — grava o veredito de cada grupo
    assim que ele termina, para a tela Eventos poder mostrar o agente
    trabalhando em tempo real (em vez de só no fim, até ~900s depois)."""
    async with SessionLocal() as db:
        event = await db.get(Event, event_id)
        if not event or event.rules_engine_status not in ("pending", "analyzing"):
            return
        trace = dict(event.rules_engine_verdict or {})
        groups = dict(trace.get("groups") or {})
        groups[stage] = group_verdict
        trace["groups"] = groups
        trace["stage"] = stage
        trace["stages_done"] = len(groups)
        trace["stages_total"] = len(_STAGE_ORDER)
        event.rules_engine_verdict = trace
        event.rules_engine_status = "analyzing"
        await db.commit()


# Teto ABSOLUTO pra análise de um único evento (bem acima de
# `_TOTAL_TIMEOUT_SECONDS`, 900s, o teto já existente dentro de
# `analyze_event`/graph.py — nunca deveria disparar por uma análise
# legítima, só longa). Achado real de teste de carga, nunca isolado com
# certeza apesar de investigação extensa (py-spy, pg_stat_activity,
# pg_locks, diagnóstico dedicado): sob rajada sustentada, uma fração dos
# eventos ficava presa segurando a vaga do semáforo `_INGEST_PROCESSING_
# CONCURRENCY`/`_ANALYSIS_CONCURRENCY` indefinidamente, mesmo depois de
# excluídas hipóteses concretas (spawn de subprocesso MCP repetido,
# concorrência na sessão MCP persistente, cancelamento inseguro de uma
# `AsyncSession` compartilhada). O timeout do Postgres
# (`idle_in_transaction_session_timeout`, app/db.py) já limpa a conexão
# travada sozinho, mas isso não devolve a vaga do semáforo — é só um
# objeto Python em memória, o Postgres não sabe que ele existe. Isto é a
# rede de segurança final: NENHUM evento consegue segurar uma vaga pra
# sempre, seja qual for a causa exata (conhecida ou não) do travamento.
_EVENT_PROCESSING_HARD_CEILING_SECONDS = 1200.0


async def run_rules_engine_for_event(event_id: int) -> None:
    try:
        await asyncio.wait_for(_run_rules_engine_for_event(event_id), timeout=_EVENT_PROCESSING_HARD_CEILING_SECONDS)
    except Exception as exc:  # noqa: BLE001 — nunca deixa um evento preso pra sempre em "pending"/"analyzing"
        # Achado real de teste de carga: quando o Postgres derruba uma
        # conexão sozinho (`idle_in_transaction_session_timeout`,
        # app/db.py), a PRÓXIMA operação da task que a usava levanta uma
        # exceção real (a conexão não existe mais) — a vaga do semáforo
        # libera certinho (o `async with` dentro de `_run_rules_engine_for_
        # event` trata isso), mas o EVENTO em si nunca chegava a ter seu
        # status final gravado, porque a sessão que faria isso é a MESMA que
        # acabou de quebrar. Ficava "analyzing" para sempre — nem erro
        # visível, nem reprocessado no próximo restart (só "pending"/
        # "analyzing" são requeued, e ele já parecia estar sendo
        # processado). Sessão NOVA aqui de propósito — nunca reaproveita a
        # que pode estar com o estado interno corrompido pela falha.
        try:
            async with SessionLocal() as db:
                event = await db.get(Event, event_id)
                if event and event.rules_engine_status in ("pending", "analyzing"):
                    event.rules_engine_status = "no_match"
                    event.rules_engine_verdict = {
                        "matched": False, "matched_skills": [],
                        "summary": f"Análise interrompida por falha técnica: {exc}"[:300],
                        "recommendation": "Falha técnica durante a análise — revisar manualmente e reenviar o evento se necessário.",
                        "groups": {}, "technical_failure": True,
                    }
                    event.analyzed_at = datetime.now(timezone.utc)
                    await db.commit()
        except Exception:  # noqa: BLE001 — a limpeza também pode falhar; não deixa isso propagar
            pass


async def _run_rules_engine_for_event(event_id: int) -> None:
    # `_INGEST_PROCESSING_CONCURRENCY` cobre só esta fase (leituras rápidas +
    # vias rápidas) — de propósito, NÃO cobre a espera pela IA mais abaixo.
    # Achado real de teste de carga: quando as duas coisas dividiam o MESMO
    # semáforo, um evento que precisava de IA ficava segurando uma das 12
    # vagas o tempo TODO que esperava sua vez em `_ANALYSIS_CONCURRENCY`
    # (agora 1) — com poucos eventos de IA já bastava pra esgotar as 12
    # vagas e bloquear até eventos puramente determinísticos (sem NENHUMA
    # chance de IA) atrás deles na fila. Medido ao vivo: 54 de 63 eventos
    # que resolveram sem qualquer chamada de LLM ainda assim levaram 600-
    # 1900s, presos atrás de outros esperando a vez no Ollama. Soltar a vaga
    # de ingestão antes de entrar na fila de IA elimina esse bloqueio de
    # cabeça de fila — um evento determinístico nunca mais espera por um que
    # nem é da mesma "fila" de verdade.
    async with _INGEST_PROCESSING_CONCURRENCY:
        async with SessionLocal() as db:
            event = await db.get(Event, event_id)
            if not event:
                return

            event.correlated_count = await count_recent_events_from_ip(db, event.src_ip, before=event.received_at)
            incident_context = await _open_incident_context(db, event.src_ip, before=event.received_at)
            campaign_context = await _campaign_context(db, event, before=event.received_at)
            incident_context = " ".join(filter(None, [incident_context, campaign_context])) or None

            if is_compliance_noise(event.raw or {}):
                # Via rápida: achado de compliance/inventário (SCA/rootcheck) —
                # veredito determinístico, sem gastar o único worker de LLM com
                # algo que não é um comportamento de ataque. Ver event_triage.py.
                verdict = fast_lane_verdict(event.type)
                event.rules_engine_verdict = verdict
                event.matched_skills = []
                event.rules_engine_status = "informational"
                event.recommendation = verdict["recommendation"]
                event.analyzed_at = datetime.now(timezone.utc)
                await db.commit()
                return

            if not is_network_traffic(src_ip=event.src_ip, dst_ip=event.dst_ip):
                # Escopo do produto: só analisamos tráfego de rede. Telemetria de
                # host sem IP nenhum (FIM, rootcheck, syscollector, ciclo de vida
                # do agente, sudo/tela bloqueada) nunca chega ao motor de IA — só
                # o rótulo de compliance (acima) tinha esse tratamento antes;
                # isso generaliza para qualquer evento sem sinal de rede.
                verdict = non_network_fast_lane_verdict(event.type)
                event.rules_engine_verdict = verdict
                event.matched_skills = []
                event.rules_engine_status = "informational"
                event.recommendation = verdict["recommendation"]
                event.analyzed_at = datetime.now(timezone.utc)
                await db.commit()
                return

            payload = {
                "type": event.type, "severity": event.severity, "src_ip": event.src_ip,
                "src_port": event.src_port, "dst_ip": event.dst_ip, "dst_port": event.dst_port,
                "protocol": event.protocol, "mitre": event.mitre, "behavior": event.behavior,
                "hit_count": event.hit_count, "rule_ref": event.rule_ref, "enrichment": event.enrichment,
                "correlated_count": event.correlated_count, "incident_context": incident_context,
            }

            # Via rápida determinística: duas fontes de fato objetivo, sem RAG/
            # LLM — (1) app/services/correlation_rules.py (CSOC-00x: porta,
            # tentativas/correlação, reputação de IP, já calculadas acima e no
            # ingest) e (2) app/services/skill_signature_match.py (SID Suricata /
            # regra ModSecurity que a própria fonte já relatou E que o catálogo
            # real de skills reconhece — mesmo princípio de _exact_id_matches
            # para MITRE ATT&CK em app/agents/graph.py, mas para os OUTROS
            # catálogos: Suricata, ModSecurity). Isso é o que faz a decisão
            # acontecer em segundos em vez de esperar o grafo sequencial (3
            # grupos + supervisor, cada um em Ollama CPU) mesmo para assinaturas
            # de rede reais e já catalogadas — só o que sobra disso (nenhuma das
            # duas fontes reconheceu nada) vai para o motor de IA.
            deterministic_matches = correlation_rules.evaluate(payload) + skill_signature_match.evaluate(event.raw or {})
            fast_verdict = deterministic_verdict(deterministic_matches) if deterministic_matches else None
            if fast_verdict is not None:
                event.rules_engine_verdict = fast_verdict
                event.matched_skills = fast_verdict["matched_skills"]
                event.rules_engine_status = "matched"
                event.recommendation = fast_verdict["recommendation"]
                # `_translate_wazuh` só grava o MITRE que a PRÓPRIA fonte relatou
                # na ingestão (raro para Suricata/ModSecurity — a maioria das
                # regras do ET-Open/OWASP CRS não embute a técnica na assinatura
                # em si). A via rápida sabe mais do que isso: uma vez confirmado
                # que o SID/regra bate o catálogo real, `skill_signature_match.py`
                # já traduz classtype/categoria em técnica ATT&CK — sem isso, um
                # evento podia ter skill confirmada e ainda assim `mitre=[]`.
                for technique_id in fast_verdict.get("mitre") or []:
                    if technique_id not in event.mitre:
                        event.mitre = [*event.mitre, technique_id]
                event.risk_score = _escalate_risk_score(
                    event.risk_score, correlated_count=event.correlated_count, deterministic=True,
                )
                event.analyzed_at = datetime.now(timezone.utc)
                await db.commit()
                await _open_or_fuse_incident(db, event)
                return

            # Aprendizado incremental (app/services/learning.py): a IA já
            # confirmou este MESMO `type` de alerta (a descrição que a própria
            # fonte dá) `learning.PROMOTION_THRESHOLD` vezes ou mais antes —
            # reconhece sem gastar outra chamada de LLM. Isto é o que faz a
            # plataforma ficar mais rápida com o volume real recebido em vez de
            # reprocessar do zero pra sempre ("100% de eficiência" sem nunca
            # aprender nada, achado real desta validação).
            learned = await learning.lookup(db, event.type)
            if learned is not None:
                learned_verdict = learning.learned_verdict(learned)
                event.rules_engine_verdict = learned_verdict
                event.matched_skills = learned_verdict["matched_skills"]
                event.rules_engine_status = "matched"
                event.recommendation = learned_verdict["recommendation"]
                for technique_id in learned_verdict.get("mitre") or []:
                    if technique_id not in event.mitre:
                        event.mitre = [*event.mitre, technique_id]
                event.risk_score = _escalate_risk_score(
                    event.risk_score, correlated_count=event.correlated_count, deterministic=True,
                )
                event.analyzed_at = datetime.now(timezone.utc)
                await db.commit()
                await _open_or_fuse_incident(db, event)
                return

            event.rules_engine_status = "analyzing"
            await db.commit()

    async def on_progress(stage: str, group_verdict: dict) -> None:
        await _persist_progress(event_id, stage, group_verdict)

    async with _ANALYSIS_CONCURRENCY:
        verdict = await analyze_event(payload, on_progress=on_progress)

    async with SessionLocal() as db:
        event = await db.get(Event, event_id)
        if not event:
            return
        event.rules_engine_verdict = verdict
        event.matched_skills = verdict.get("matched_skills") or []
        event.rules_engine_status = "matched" if verdict.get("matched") else "no_match"
        event.recommendation = verdict.get("recommendation")
        if verdict.get("matched"):
            event.risk_score = _escalate_risk_score(
                event.risk_score, correlated_count=event.correlated_count, deterministic=False,
            )
            # Só o grupo attack_defend busca no catálogo ATT&CK/D3FEND — as
            # "skills" dele JÁ SÃO técnica MITRE (`_exact_id_matches`,
            # app/agents/graph.py, compara contra `external_id` da skill).
            # As dos outros dois grupos (network_signature/web_application)
            # são SID Suricata / id de regra ModSecurity, formatos próprios
            # que não podem ir para `event.mitre` sem tradução — mesmo gap
            # de hidratação da via rápida, agora fechado também no caminho
            # que passou pela IA.
            attack_defend_skills = (verdict.get("groups") or {}).get("attack_defend", {}).get("skills") or []
            for technique_id in attack_defend_skills:
                if technique_id not in event.mitre:
                    event.mitre = [*event.mitre, technique_id]
            # A verificação em graph.py::supervisor_node já garante que
            # "matched" nunca vem de skill inventada — seguro promover este
            # `type` para aprendizado incremental.
            await learning.record_confirmation(db, event.type, verdict)
        elif not any(g.get("degraded") for g in (verdict.get("groups") or {}).values()):
            # Nenhuma skill do catálogo casou (análise completa, não
            # degradada) — mas "sem skill conhecida" não é o mesmo que "sem
            # sinal nenhum". Confere contra a linha de base de 7 dias desta
            # origem (app/services/baseline.py): uma origem nova gerando uma
            # rajada, ou uma origem historicamente esporádica muito acima do
            # próprio padrão, vira "suspeito" para investigação humana
            # depois, em vez de descartado como "no_match" — pedido real:
            # não focar só no evento isolado, olhar a janela da semana.
            weekly = await weekly_activity(db, event.src_ip, before=event.received_at)
            reason = anomaly_reason(weekly, current_correlated_count=event.correlated_count or 0)
            if reason:
                event.rules_engine_status = "suspicious"
                event.recommendation = (
                    f"{reason} Nenhuma skill do catálogo confirmou uma técnica específica — "
                    "flag para averiguação manual, não uma detecção confirmada."
                )
                event.rules_engine_verdict = {**verdict, "flagged_reason": reason, "weekly_activity": weekly}
        event.analyzed_at = datetime.now(timezone.utc)
        await db.commit()

        if verdict.get("matched"):
            await _open_or_fuse_incident(db, event)
