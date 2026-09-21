from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import Select, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth.deps import current_user
from ..db import get_db
from ..models import Connector, Event, Incident, LearnedPattern, User
from ..services.asm import list_exposed_assets
from ..services.asset_risk import ASSET_RISK_WINDOW_DAYS, compute_asset_risk
from ..services.mitre import MITRE_TACTICS, technique_tactic_pt
from ..services.narrative import build_activity_timeline, build_incident_narratives, build_traffic_baseline_overview

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

SEVERITIES = ("critica", "alta", "media", "baixa", "info")


def _tag_filter(stmt: Select, tag: str | None) -> Select:
    return stmt.where(Event.tag == tag) if tag else stmt


@router.get("/tags")
async def tags(db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    """Tags de cliente distintas vistas nos eventos — alimenta o seletor do
    dashboard ("ver só os eventos da VALID")."""
    rows = (await db.execute(select(Event.tag).where(Event.tag.is_not(None)).distinct())).scalars().all()
    return {"tags": sorted(rows)}


@router.get("/summary")
async def summary(tag: str | None = None, db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    now = datetime.now(timezone.utc)
    today_start = datetime.combine(now.date(), datetime.min.time(), tzinfo=timezone.utc)

    counts = {s: 0 for s in SEVERITIES}
    rows = (
        await db.execute(_tag_filter(select(Event.severity, func.count(Event.id)), tag).group_by(Event.severity))
    ).all()
    for severity, count in rows:
        counts[severity] = int(count or 0)

    events_today = int((
        await db.execute(_tag_filter(select(func.count(Event.id)), tag).where(Event.timestamp >= today_start))
    ).scalar() or 0)

    avg_risk = (await db.execute(_tag_filter(select(func.avg(Event.risk_score)), tag))).scalar()

    seen = {
        t for (items,) in (await db.execute(_tag_filter(select(Event.mitre), tag))).all() for t in (items or [])
    }
    total_techniques = sum(len(t["techniques"]) for t in MITRE_TACTICS)
    covered = len([t for t in seen if t in {tech for tac in MITRE_TACTICS for tech in tac["techniques"]}])
    mitre_pct = round(covered * 100 / total_techniques) if total_techniques else 0

    return {
        "date": now.isoformat(),
        "severity_counts": counts,
        "events_today": events_today,
        "critical_active": counts.get("critica", 0),
        "avg_risk_score": round(float(avg_risk), 1) if avg_risk is not None else 0.0,
        "mitre_coverage_pct": mitre_pct,
    }


@router.get("/eps")
async def eps(tag: str | None = None, db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    """EPS + funil: TOTAL de EPS ingerido -> motor de regras de IA (Supervisor
    LangGraph + skills ATT&CK/D3FEND/Suricata/ModSecurity via RAG/MCP,
    `app/agents/graph.py`) -> Incidentes. O estágio do meio é
    `rules_engine_status == "matched"` (dado real da análise, roda em
    background após a ingestão — não é um limiar estático)."""
    now = datetime.now(timezone.utc)
    count_1m = int((
        await db.execute(_tag_filter(select(func.count(Event.id)), tag).where(Event.received_at >= now - timedelta(minutes=1)))
    ).scalar() or 0)
    count_5m = int((
        await db.execute(_tag_filter(select(func.count(Event.id)), tag).where(Event.received_at >= now - timedelta(minutes=5)))
    ).scalar() or 0)

    total = int((await db.execute(_tag_filter(select(func.count(Event.id)), tag))).scalar() or 0)
    matched_stmt = _tag_filter(select(func.count(Event.id)), tag).where(Event.rules_engine_status == "matched")
    matched = int((await db.execute(matched_stmt)).scalar() or 0)
    pending_stmt = _tag_filter(select(func.count(Event.id)), tag).where(
        Event.rules_engine_status.in_(("pending", "analyzing"))
    )
    pending = int((await db.execute(pending_stmt)).scalar() or 0)

    incident_count_stmt = select(func.count(Incident.id))
    if tag:
        incident_count_stmt = incident_count_stmt.where(Incident.tag == tag)
    incidents_total = int((await db.execute(incident_count_stmt)).scalar() or 0)

    # Delay de análise "agora": recebido -> veredito terminal, só dos últimos
    # 5 minutos (mesma janela do `avg_5m` acima) — reflete a velocidade atual
    # do pipeline, não uma média histórica que um pico antigo de LLM lento
    # deixaria enganosamente alta. `None` (não 0) quando não há evento
    # analisado na janela, para o front distinguir "sem delay" de "sem dado".
    recent_analyzed_stmt = _tag_filter(select(Event.received_at, Event.analyzed_at), tag).where(
        Event.analyzed_at.is_not(None), Event.analyzed_at >= now - timedelta(minutes=5)
    )
    recent_analyzed = (await db.execute(recent_analyzed_stmt)).all()
    delay_seconds = None
    if recent_analyzed:
        deltas = []
        for received_at, analyzed_at in recent_analyzed:
            received = received_at if received_at.tzinfo else received_at.replace(tzinfo=timezone.utc)
            analyzed = analyzed_at if analyzed_at.tzinfo else analyzed_at.replace(tzinfo=timezone.utc)
            deltas.append((analyzed - received).total_seconds())
        delay_seconds = round(sum(deltas) / len(deltas), 2)

    funnel = [
        {"stage": "eps", "label": "Total de EPS", "count": total, "pct_of_total": 100.0 if total else 0.0},
        {"stage": "rules_engine", "label": "Motor de Regras (IA)", "count": matched,
         "pct_of_total": round(matched * 100 / total, 1) if total else 0.0},
        {"stage": "incident", "label": "Incidentes", "count": incidents_total,
         "pct_of_total": round(incidents_total * 100 / total, 2) if total else 0.0},
    ]

    return {
        "eps": {"current": round(count_1m / 60, 2), "avg_5m": round(count_5m / 300, 2)},
        "total_events": total,
        "pending_analysis": pending,
        "analysis_delay_seconds": delay_seconds,
        "funnel": funnel,
    }


@router.get("/mitre-heatmap")
async def mitre_heatmap(tag: str | None = None, db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    rows = (await db.execute(_tag_filter(select(Event.mitre), tag))).all()
    counts: dict[str, int] = {}
    for (items,) in rows:
        for tech in items or []:
            counts[tech] = counts.get(tech, 0) + 1

    tactics = []
    max_count = 0
    for tactic in MITRE_TACTICS:
        cells = []
        for tech in tactic["techniques"]:
            c = counts.get(tech, 0)
            max_count = max(max_count, c)
            cells.append({"id": tech, "count": c})
        tactics.append({"name": tactic["name"], "techniques": cells})
    return {"tactics": tactics, "max_count": max_count}


@router.get("/risk-heatmap")
async def risk_heatmap(tag: str | None = None, db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    """Heat map de risco do ambiente: dia da semana x hora, célula = risco médio
    dos eventos daquela janela (não apenas volume) dos últimos 7 dias."""
    since = datetime.now(timezone.utc) - timedelta(days=7)
    grid = [[0.0] * 24 for _ in range(7)]
    counts = [[0] * 24 for _ in range(7)]

    stmt = _tag_filter(select(Event.timestamp, Event.risk_score), tag).where(Event.timestamp >= since)
    rows = (await db.execute(stmt)).all()
    for ts, risk in rows:
        aware = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        d, h = aware.weekday(), aware.hour
        grid[d][h] += risk or 0
        counts[d][h] += 1

    for d in range(7):
        for h in range(24):
            grid[d][h] = round(grid[d][h] / counts[d][h], 1) if counts[d][h] else 0.0

    return {"days": ["Seg", "Ter", "Qua", "Qui", "Sex", "Sáb", "Dom"], "grid": grid, "max_risk": 100}


@router.get("/world-map")
async def world_map(tag: str | None = None, db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    """Pins do world map: origem geográfica dos eventos (agrupado por
    cidade/coordenada), com contagem e severidade máxima observada."""
    stmt = _tag_filter(
        select(Event.country, Event.city, Event.lat, Event.lon, Event.severity, Event.risk_score), tag
    ).where(Event.lat.is_not(None), Event.lon.is_not(None))
    rows = (await db.execute(stmt)).all()

    rank = {"critica": 4, "alta": 3, "media": 2, "baixa": 1, "info": 0}
    points: dict[tuple, dict] = {}
    for country, city, lat, lon, severity, risk in rows:
        key = (round(lat, 1), round(lon, 1))
        p = points.setdefault(key, {
            "country": country, "city": city, "lat": lat, "lon": lon,
            "count": 0, "max_severity": "info", "max_risk": 0,
        })
        p["count"] += 1
        p["max_risk"] = max(p["max_risk"], risk or 0)
        if rank.get(severity, 0) > rank.get(p["max_severity"], 0):
            p["max_severity"] = severity

    return {"points": list(points.values())}


@router.get("/connectors-status")
async def connectors_status(db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    """"Tratativa atual" — status das plataformas de acesso (conectores) configuradas."""
    rows = (await db.execute(select(Connector))).scalars().all()
    return {
        "total": len(rows),
        "items": [
            {
                "id": c.id, "name": c.name, "kind": c.kind, "type": c.type,
                "status": c.status, "last_test": c.last_test,
                "client_tag": (c.config or {}).get("client_tag"),
            }
            for c in rows
        ],
    }


@router.get("/incidents-status")
async def incidents_status(tag: str | None = None, db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    """Status dos incidentes internos (BackLog / Em Andamento / Concluído)."""
    stmt = select(Incident.status, func.count(Incident.id))
    if tag:
        stmt = stmt.where(Incident.tag == tag)
    rows = (await db.execute(stmt.group_by(Incident.status))).all()
    by_status = {s: int(c) for s, c in rows}

    recent_stmt = select(Incident).order_by(Incident.created_at.desc()).limit(8)
    if tag:
        recent_stmt = recent_stmt.where(Incident.tag == tag)
    recent = (await db.execute(recent_stmt)).scalars().all()

    return {
        "summary": {
            "backlog": by_status.get("backlog", 0),
            "em_andamento": by_status.get("em_andamento", 0),
            "concluido": by_status.get("concluido", 0),
            "total": sum(by_status.values()),
        },
        "recent": [
            {
                "id": i.id, "code": i.code, "title": i.title, "status": i.status, "severity": i.severity,
                "event_id": i.event_id, "glpi_ticket_id": i.glpi_ticket_id,
            }
            for i in recent
        ],
    }


def _duration_stats(seconds: list[float]) -> dict:
    if not seconds:
        return {"avg_seconds": None, "median_seconds": None, "p95_seconds": None, "sample_size": 0}
    ordered = sorted(seconds)
    n = len(ordered)
    p95 = ordered[min(n - 1, int(n * 0.95))]
    mid = n // 2
    median = ordered[mid] if n % 2 else (ordered[mid - 1] + ordered[mid]) / 2
    return {
        "avg_seconds": round(sum(ordered) / n, 1),
        "median_seconds": round(median, 1),
        "p95_seconds": round(p95, 1),
        "sample_size": n,
    }


@router.get("/analysis-metrics")
async def analysis_metrics(tag: str | None = None, db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    """Estabilidade, velocidade e SLA reais do motor de regras — calculados a
    partir de timestamps de banco (received_at/analyzed_at/created_at), nunca
    estimados. Existe porque "qual a %", "qual a velocidade" e "qual o SLA"
    são perguntas concretas que a plataforma precisa responder com dado real,
    não só mostrar o veredito de cada evento isoladamente."""
    now = datetime.now(timezone.utc)

    analyzed_stmt = _tag_filter(
        select(Event.received_at, Event.analyzed_at, Event.rules_engine_verdict), tag
    ).where(Event.rules_engine_status.in_(("matched", "no_match", "suspicious")), Event.analyzed_at.is_not(None))
    analyzed_rows = (await db.execute(analyzed_stmt)).all()

    speed_seconds: list[float] = []
    degraded_count = 0
    grounding_rejected_count = 0
    deterministic_count = 0
    for received_at, analyzed_at, verdict in analyzed_rows:
        received = received_at if received_at.tzinfo else received_at.replace(tzinfo=timezone.utc)
        analyzed = analyzed_at if analyzed_at.tzinfo else analyzed_at.replace(tzinfo=timezone.utc)
        speed_seconds.append((analyzed - received).total_seconds())
        groups = (verdict or {}).get("groups") or {}
        if any(g.get("degraded") for g in groups.values()):
            degraded_count += 1
        if (verdict or {}).get("grounding_rejected"):
            grounding_rejected_count += 1
        # Quantos eventos tiveram pelo menos um grupo resolvido por
        # correspondência exata de técnica (app/agents/graph.py
        # _exact_id_matches) em vez de precisar do LLM — via rápida real,
        # não julgamento do modelo. Sinal direto do catálogo unificado por
        # técnica MITRE (skills_catalog.py): antes da unificação, os grupos
        # network_signature/web_application nunca tinham candidatas com
        # external_id no formato de técnica ATT&CK (eram SID/rule-id/UUID
        # crus da fonte), então essa via nunca disparava para eles.
        if any(g.get("deterministic") for g in groups.values()):
            deterministic_count += 1

    total_analyzed = len(analyzed_rows)
    # Renomeado de "eficiência" (achado real: o rótulo sozinho passava a
    # impressão de qualidade/acerto da decisão, mas isto só mede se a
    # chamada de IA COMPLETOU sem cair pra um grupo mais fraco por
    # indisponibilidade — infraestrutura, não correção. Uma alucinação do
    # Supervisor (matched_skills inventado) nunca contava como degradação
    # (a chamada respondeu normalmente, só errado) — por isso isto ficava
    # em 100% o tempo todo enquanto o bug de aterramento gerava incidentes
    # falsos. `grounding_rejected_count` (abaixo) é o sinal de qualidade de
    # verdade: quantas vezes a validação teve que corrigir o Supervisor.
    stability_pct = round((total_analyzed - degraded_count) * 100 / total_analyzed, 1) if total_analyzed else None

    fast_lane_stmt = _tag_filter(select(func.count(Event.id)), tag).where(Event.rules_engine_status == "informational")
    fast_lane_count = int((await db.execute(fast_lane_stmt)).scalar() or 0)

    # `efficiency_pct` acima só mede se a análise de IA COMPLETOU sem
    # degradar (RAG/LLM caiu para um grupo mais fraco) — nunca foi, e não
    # deveria ser lido como, "os dados do evento estão completos". Um evento
    # pode ter 0% de degradação e mesmo assim não carregar nem técnica MITRE
    # nem enriquecimento de threat intel (achado real: `mitre_coverage_pct`
    # ficou em 0% por meses com `efficiency_pct` em 100% o tempo todo — a
    # causa raiz era o Wazuh nunca preencher `rule.mitre` para alertas do
    # Suricata, não a IA). `hydration_pct` mede exatamente essa outra
    # pergunta — dos eventos que o motor confirmou como "casou uma skill",
    # quantos carregam de fato técnica MITRE e/ou enriquecimento de IP —
    # para não ler "100%" onde o dado real é raso. `enrichment` sempre tem as
    # chaves abuseipdb/shodan/assessment (`analyze_traffic`,
    # threat_intel.py) mesmo sem nenhum provedor configurado — `assessment`
    # é uma heurística de porta/protocolo sempre calculada, então o dict
    # nunca fica vazio de verdade; só conta como "enriquecido" se abuseipdb
    # OU shodan tiverem de fato uma resposta de provedor (não None).
    matched_stmt = _tag_filter(select(Event.mitre, Event.enrichment), tag).where(Event.rules_engine_status == "matched")
    matched_rows = (await db.execute(matched_stmt)).all()
    total_matched = len(matched_rows)
    hydrated_count = sum(
        1 for mitre, enrichment in matched_rows
        if (mitre or []) or (enrichment or {}).get("abuseipdb") or (enrichment or {}).get("shodan")
    )
    hydration_pct = round(hydrated_count * 100 / total_matched, 1) if total_matched else None

    incident_stmt = select(Event.received_at, Incident.created_at).join(Incident, Incident.event_id == Event.id)
    if tag:
        incident_stmt = incident_stmt.where(Event.tag == tag)
    incident_rows = (await db.execute(incident_stmt)).all()
    sla_seconds = []
    for received_at, created_at in incident_rows:
        received = received_at if received_at.tzinfo else received_at.replace(tzinfo=timezone.utc)
        created = created_at if created_at.tzinfo else created_at.replace(tzinfo=timezone.utc)
        sla_seconds.append((created - received).total_seconds())

    backlog_stmt = _tag_filter(select(Event.received_at), tag).where(
        Event.rules_engine_status.in_(("pending", "analyzing"))
    )
    backlog_rows = (await db.execute(backlog_stmt)).all()
    backlog_count = len(backlog_rows)
    oldest_backlog_seconds = None
    if backlog_rows:
        oldest = min(r for (r,) in backlog_rows)
        oldest = oldest if oldest.tzinfo else oldest.replace(tzinfo=timezone.utc)
        oldest_backlog_seconds = round((now - oldest).total_seconds(), 1)

    # Eventos sinalizados para investigação humana posterior (baseline.py) —
    # nem "confirmado" nem "descartado". E padrões que a IA já confirmou
    # repetidas vezes o suficiente para virar via rápida (learning.py) — a
    # prova de que a plataforma aprende com o volume real, não só reprocessa
    # do zero pra sempre.
    suspicious_stmt = _tag_filter(select(func.count(Event.id)), tag).where(Event.rules_engine_status == "suspicious")
    suspicious_count = int((await db.execute(suspicious_stmt)).scalar() or 0)
    learned_count = int((await db.execute(select(func.count(LearnedPattern.id)).where(LearnedPattern.promoted.is_(True)))).scalar() or 0)

    deterministic_pct = round(deterministic_count * 100 / total_analyzed, 1) if total_analyzed else None

    return {
        "stability_pct": stability_pct,
        "degraded_count": degraded_count,
        "grounding_rejected_count": grounding_rejected_count,
        "deterministic_pct": deterministic_pct,
        "deterministic_count": deterministic_count,
        "analyzed_by_ai_count": total_analyzed,
        "fast_lane_count": fast_lane_count,
        "hydration_pct": hydration_pct,
        "hydrated_count": hydrated_count,
        "matched_count": total_matched,
        "suspicious_count": suspicious_count,
        "learned_patterns_count": learned_count,
        "analysis_speed": _duration_stats(speed_seconds),
        "sla_event_to_incident": _duration_stats(sla_seconds),
        "backlog": {"count": backlog_count, "oldest_seconds": oldest_backlog_seconds},
    }


@router.get("/mtt-metrics")
async def mtt_metrics(tag: str | None = None, db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    """Ciclo de vida real da resposta a incidente (Visão Operacional) —
    MTTD/MTTR/MTTC/MTTR (reparo), calculados a partir de marcos REAIS do
    ticket GLPI (`sync_all_glpi_statuses`, notify.py), nunca inventados.
    Fases sequenciais, cada uma pega o fim da anterior:
      MTTD  = Incident.created_at − Event.received_at      (alerta -> identificado)
      MTTR  = glpi_takeintoaccount_at − Incident.created_at (identificado -> resposta iniciada)
      MTTC  = glpi_planned_at − glpi_takeintoaccount_at     (resposta -> bloqueio iniciado)
      MTTR* = glpi_solved_at − (planned_at ou takeintoaccount_at) (bloqueio -> ambiente seguro)
    (*"reparo" — nome em comum com "responder" no pedido original, fase diferente)

    Um incidente só entra na amostra de uma fase quando os DOIS marcos que a
    delimitam já foram observados — ainda estar em "Novo"/"Atribuído" no
    GLPI não é um erro, é o ciclo de vida dele ainda não ter chegado lá.
    `glpi_planned_at` não tem campo nativo no GLPI (o fluxo genérico dele não
    separa "contenção" de "resposta") — é a primeira vez que observamos o
    ticket em status 3 ("Processing (Planned)"), usado como proxy do início
    do bloqueio da ameaça (ver Incident.glpi_planned_at)."""
    stmt = select(
        Event.received_at, Incident.created_at,
        Incident.glpi_takeintoaccount_at, Incident.glpi_planned_at, Incident.glpi_solved_at,
    ).join(Event, Incident.event_id == Event.id)
    if tag:
        stmt = stmt.where(Event.tag == tag)
    rows = (await db.execute(stmt)).all()

    def _aware(dt: datetime) -> datetime:
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

    mttd: list[float] = []
    mttr_respond: list[float] = []
    mttc_contain: list[float] = []
    mttr_repair: list[float] = []
    for received_at, created_at, takeintoaccount_at, planned_at, solved_at in rows:
        created = _aware(created_at)
        mttd.append((created - _aware(received_at)).total_seconds())
        if takeintoaccount_at is None:
            continue
        tia = _aware(takeintoaccount_at)
        mttr_respond.append((tia - created).total_seconds())
        contain_end = tia
        if planned_at is not None:
            contain_end = _aware(planned_at)
            mttc_contain.append((contain_end - tia).total_seconds())
        if solved_at is not None:
            mttr_repair.append((_aware(solved_at) - contain_end).total_seconds())

    return {
        "mttd": _duration_stats(mttd),
        "mttr_respond": _duration_stats(mttr_respond),
        "mttc_contain": _duration_stats(mttc_contain),
        "mttr_repair": _duration_stats(mttr_repair),
    }


_ATTACK_VECTOR_RESULTS = ("matched", "no_match", "suspicious")


@router.get("/attack-vector")
async def attack_vector(tag: str | None = None, db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    """Tratamento de eventos por fonte de dado x vetor de ataque (tática
    MITRE do evento, ou "Sem técnica MITRE" quando nenhuma foi identificada)
    — cada célula mostra como aquela combinação se resolveu (confirmado/sem
    ameaça/suspeito). Não é uma matriz de confusão de ML de verdade (não
    existe rótulo de verdade fundamental aqui) — é o resultado real por
    fonte x vetor, para achar se uma fonte específica gera desproporcionalmente
    mais falsos positivos (ou mais confirmações) num vetor específico."""
    stmt = _tag_filter(select(Event.source, Event.mitre, Event.rules_engine_status), tag)
    rows = (await db.execute(stmt)).all()

    cells: dict[tuple[str, str], dict[str, int]] = {}
    sources: set[str] = set()
    categories: set[str] = set()
    for source, mitre, status in rows:
        category = technique_tactic_pt(mitre[0]) if mitre else "Sem técnica MITRE"
        sources.add(source)
        categories.add(category)
        cell = cells.setdefault((source, category), {"total": 0, "matched": 0, "no_match": 0, "suspicious": 0, "other": 0})
        cell["total"] += 1
        if status in _ATTACK_VECTOR_RESULTS:
            cell[status] += 1
        else:
            cell["other"] += 1

    category_totals = {c: sum(cells.get((s, c), {}).get("total", 0) for s in sources) for c in categories}
    ordered_categories = sorted(categories, key=lambda c: category_totals[c], reverse=True)

    return {
        "sources": sorted(sources),
        "categories": ordered_categories,
        "cells": [
            {"source": s, "category": c, **cells[(s, c)]}
            for (s, c) in cells
        ],
    }


# Prazo-alvo por severidade (horas) — referência padrão de SOC, não um valor
# contratual real de nenhum cliente específico; existe pra dar um "% dentro
# do SLA" honesto em vez de nenhum. Ajustável aqui até virar configurável de
# verdade por cliente/conector.
_SLA_TARGET_HOURS: dict[str, float] = {"critica": 4.0, "alta": 24.0, "media": 72.0, "baixa": 168.0, "info": 168.0}


@router.get("/kpis")
async def kpis(tag: str | None = None, db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    """SLA%, redução de carga de trabalho e relevância por fonte (documentação
    Inopli — KPIs Dashboard / Executive Dashboard / Data Sources) — cada um
    calculado só a partir de dado real já existente, nunca inventado."""

    def _aware(dt: datetime) -> datetime:
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

    # SLA: % de incidentes RESOLVIDOS dentro do prazo-alvo da própria
    # severidade. "Resolvido" usa a mesma referência que MTTR (reparo) já usa
    # (glpi_solved_at) — glpi_closed_at como reserva para o ticket que pula
    # direto pra Fechado sem passar por Resolvido.
    resolved_stmt = _tag_filter(
        select(Incident.severity, Incident.created_at, Incident.glpi_solved_at, Incident.glpi_closed_at), tag,
    ).where(or_(Incident.glpi_solved_at.is_not(None), Incident.glpi_closed_at.is_not(None)))
    resolved_rows = (await db.execute(resolved_stmt)).all()
    sla_total = len(resolved_rows)
    sla_compliant = 0
    for severity, created_at, solved_at, closed_at in resolved_rows:
        resolved_at = _aware(solved_at or closed_at)
        target_hours = _SLA_TARGET_HOURS.get(severity, 72.0)
        if (resolved_at - _aware(created_at)).total_seconds() <= target_hours * 3600:
            sla_compliant += 1
    sla_compliance_pct = round(sla_compliant * 100 / sla_total, 1) if sla_total else None

    # Redução de carga de trabalho: dos eventos recebidos, quantos NUNCA
    # precisaram virar um incidente (trabalho real pra um analista) — o resto
    # foi triado automaticamente (sem skill real, informativo, ou ainda em
    # análise). Mede o motor de regras como um todo, não só a via de IA
    # (`deterministic_pct` em /analysis-metrics mede uma pergunta diferente:
    # dos eventos QUE PRECISARAM de análise, quantos vieram de fato objetivo).
    total_events = int((await db.execute(_tag_filter(select(func.count(Event.id)), tag))).scalar() or 0)
    incidents_stmt = select(func.count(Incident.id))
    if tag:
        incidents_stmt = incidents_stmt.where(Incident.tag == tag)
    total_incidents = int((await db.execute(incidents_stmt)).scalar() or 0)
    workload_reduction_pct = round((1 - total_incidents / total_events) * 100, 1) if total_events else None

    # Fontes de dado: do total recebido por fonte, quanto foi "relevante" de
    # verdade (skill confirmada ou sinalizado como suspeito) — acha se uma
    # fonte específica manda desproporcionalmente mais ruído que as outras.
    source_rows = (await db.execute(_tag_filter(select(Event.source, Event.rules_engine_status), tag))).all()
    by_source: dict[str, dict[str, int]] = {}
    for source, status in source_rows:
        entry = by_source.setdefault(source, {"total": 0, "relevant": 0})
        entry["total"] += 1
        if status in ("matched", "suspicious"):
            entry["relevant"] += 1

    return {
        "sla": {
            "target_hours": _SLA_TARGET_HOURS,
            "compliant": sla_compliant, "total": sla_total, "compliance_pct": sla_compliance_pct,
        },
        "workload_reduction_pct": workload_reduction_pct,
        "data_sources": [
            {
                "source": s, "total": v["total"], "relevant": v["relevant"],
                "relevant_pct": round(v["relevant"] * 100 / v["total"], 1) if v["total"] else None,
            }
            for s, v in sorted(by_source.items())
        ],
    }


def _safe_pct(numerator: int, denominator: int) -> float | None:
    return round(numerator * 100 / denominator, 1) if denominator else None


@router.get("/confusion-matrix")
async def confusion_matrix(tag: str | None = None, db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    """Matriz de confusão REAL (Verdadeiro/Falso Positivo/Negativo) — a
    diferença do "Attack Vector" (que usa o PRÓPRIO veredito do motor como
    proxy, nunca um rótulo de verdade) é que aqui a fonte é a reclassificação
    HUMANA (`Event.analyst_verdict`, ver events.py `PATCH /{id}/verdict`).
    Só conta o que já foi revisado — `reviewed_count`/`total_events` mostra a
    cobertura da amostra; Precisão/Recall/etc. sobre poucos eventos revisados
    não tem o mesmo peso que sobre uma amostra grande, e cada % fica `None`
    (nunca 0% enganoso) quando o denominador ainda é zero."""
    rows = (await db.execute(
        _tag_filter(select(Event.analyst_verdict, func.count(Event.id)), tag).group_by(Event.analyst_verdict)
    )).all()
    counts = {verdict: int(count) for verdict, count in rows if verdict is not None}
    tp, fp = counts.get("true_positive", 0), counts.get("false_positive", 0)
    tn, fn = counts.get("true_negative", 0), counts.get("false_negative", 0)
    reviewed = tp + fp + tn + fn
    total_events = int((await db.execute(_tag_filter(select(func.count(Event.id)), tag))).scalar() or 0)

    precision = _safe_pct(tp, tp + fp)
    recall = _safe_pct(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 1) if precision and recall and (precision + recall) else None

    return {
        "true_positive": tp, "false_positive": fp, "true_negative": tn, "false_negative": fn,
        "reviewed_count": reviewed, "total_events": total_events,
        "accuracy_pct": _safe_pct(tp + tn, reviewed),
        "precision_pct": precision,
        "recall_pct": recall,
        "f1_pct": f1,
        "false_positive_rate_pct": _safe_pct(fp, fp + tn),
        "false_negative_rate_pct": _safe_pct(fn, fn + tp),
    }


@router.get("/asset-risk")
async def asset_risk(tag: str | None = None, db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    """Ativos (hostname/IP) observados nos eventos recebidos, ranqueados por
    risco calculado do histórico real (services/asset_risk.py) — nunca um
    cadastro manual de CMDB. Janela de 30 dias: um ativo silencioso há mais
    tempo que isso sai do ranking sozinho, sem precisar de expiração manual."""
    items = await compute_asset_risk(db, tag=tag)
    return {"window_days": ASSET_RISK_WINDOW_DAYS, "items": items}


@router.get("/exposed-assets")
async def exposed_assets(db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    """ASM mínimo (services/asm.py): IPs públicos de destino observados nos
    eventos recebidos + o que o Shodan já sabe sobre eles (portas/serviços
    expostos), quando um conector Shodan estiver habilitado. Primeiro corte
    de superfície de ataque reaproveitando a MESMA integração já usada
    reativamente em threat_intel.py — não substitui uma ferramenta de ASM
    completa (sem descoberta de subdomínio/certificado)."""
    return await list_exposed_assets(db)


@router.get("/environment-seasonality")
async def environment_seasonality(db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    """Padrão temporal (dia da semana x hora) de VOLUME de eventos por
    ambiente (tag do conector) nos últimos 7 dias, com os tipos de ataque
    predominantes de cada um — "sazonalidade" de verdade: QUANDO cada
    ambiente é mais visado e POR QUE tipo de ataque, não só o risco médio
    global (ver /risk-heatmap, que não separa por ambiente nem mede volume).
    Eventos sem tag entram no balde "Sem tag" — nunca descartados em
    silêncio."""
    since = datetime.now(timezone.utc) - timedelta(days=7)
    rows = (await db.execute(select(Event.tag, Event.timestamp, Event.mitre).where(Event.timestamp >= since))).all()

    envs: dict[str, dict[str, Any]] = {}
    for tag, ts, mitre in rows:
        key = tag or "Sem tag"
        env = envs.setdefault(key, {"total_events": 0, "grid": [[0] * 24 for _ in range(7)], "attack_types": {}})
        aware = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        env["grid"][aware.weekday()][aware.hour] += 1
        env["total_events"] += 1
        category = technique_tactic_pt(mitre[0]) if mitre else "Sem técnica MITRE"
        env["attack_types"][category] = env["attack_types"].get(category, 0) + 1

    environments = []
    for env_tag, env in sorted(envs.items(), key=lambda kv: kv[1]["total_events"], reverse=True):
        top_types = sorted(env["attack_types"].items(), key=lambda kv: kv[1], reverse=True)[:5]
        environments.append({
            "tag": env_tag,
            "total_events": env["total_events"],
            "grid": env["grid"],
            "top_attack_types": [{"category": c, "count": n} for c, n in top_types],
        })

    return {"days": ["Seg", "Ter", "Qua", "Qui", "Sex", "Sáb", "Dom"], "environments": environments}


@router.get("/watchlist")
async def watchlist(tag: str | None = None, db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    """Eventos sinalizados como suspeitos (baseline.py: origem nova ou rajada
    muito acima do próprio histórico, sem nenhuma skill confirmada) — fila de
    curiosidade/averiguação para um analista revisar depois, distinta de
    "confirmado" (Incidentes) e de "nada a ver" (no_match, nem aparece aqui)."""
    stmt = _tag_filter(
        select(Event.id, Event.type, Event.src_ip, Event.dst_ip, Event.severity, Event.recommendation, Event.received_at),
        tag,
    ).where(Event.rules_engine_status == "suspicious").order_by(Event.received_at.desc()).limit(50)
    rows = (await db.execute(stmt)).all()
    return {"items": [
        {
            "id": r.id, "type": r.type, "src_ip": r.src_ip, "dst_ip": r.dst_ip, "severity": r.severity,
            "reason": r.recommendation, "received_at": r.received_at.isoformat(),
        }
        for r in rows
    ]}


@router.get("/agent-activity")
async def agent_activity(tag: str | None = None, db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    """Feed de atividade do agente (Supervisor LangGraph) — o que a IA está
    fazendo/decidindo agora, evento a evento. Existe para dar visibilidade
    real do processo (RAG + grupos + Supervisor), não só o veredito final."""
    stmt = _tag_filter(
        select(
            Event.id, Event.type, Event.severity, Event.src_ip, Event.tag,
            Event.rules_engine_status, Event.matched_skills, Event.recommendation,
            Event.rules_engine_verdict, Event.received_at,
        ),
        tag,
    ).order_by(Event.received_at.desc()).limit(12)
    rows = (await db.execute(stmt)).all()

    items = []
    for eid, etype, severity, src_ip, etag, rstatus, skills, rec, verdict, received_at in rows:
        verdict = verdict or {}
        groups = verdict.get("groups") or {}
        items.append({
            "event_id": eid, "type": etype, "severity": severity, "src_ip": src_ip, "tag": etag,
            "rules_engine_status": rstatus, "matched_skills": skills or [], "recommendation": rec,
            "stages_done": verdict.get("stages_done", len(groups)), "stages_total": verdict.get("stages_total", 3),
            "current_stage": verdict.get("stage"),
            "received_at": received_at.isoformat() if received_at else None,
        })
    return {"items": items}


@router.get("/tickets-status")
async def tickets_status(db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    """Status dos chamados abertos no GLPI a partir de incidentes desta
    plataforma (`Incident.glpi_ticket_id`, sincronizado por `sync-glpi`) —
    distinto do /incidents-status interno (que conta TODO incidente, com ou
    sem ticket)."""
    with_ticket = (await db.execute(select(Incident).where(Incident.glpi_ticket_id.is_not(None)))).scalars().all()
    if not with_ticket:
        return {
            "summary": {"abertos": 0, "em_analise": 0, "fechados": 0, "total": 0},
            "recent": [],
            "note": "Nenhum incidente gerou ticket no GLPI ainda (severidade abaixo do configurado, ou nenhum conector GLPI habilitado).",
        }
    by_status = {"abertos": 0, "em_analise": 0, "fechados": 0}
    for i in with_ticket:
        if i.status == "backlog":
            by_status["abertos"] += 1
        elif i.status == "concluido":
            by_status["fechados"] += 1
        else:
            by_status["em_analise"] += 1
    recent = sorted(with_ticket, key=lambda i: i.created_at, reverse=True)[:10]
    return {
        "summary": {**by_status, "total": len(with_ticket)},
        "recent": [
            {
                "incident_code": i.code, "glpi_ticket_id": i.glpi_ticket_id, "status": i.status,
                "glpi_synced_at": i.glpi_synced_at.isoformat() if i.glpi_synced_at else None,
            }
            for i in recent
        ],
    }


@router.get("/incident-narratives")
async def incident_narratives(tag: str | None = None, db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    """Painel N3: cada incidente aberto como HISTÓRIA (origem, há quanto
    tempo, o que já foi confirmado, status real do ticket), não só uma linha
    numa tabela — pedido real: "não dá visão pro operador/N3 do que está
    acontecendo"."""
    return {"items": await build_incident_narratives(db, tag=tag)}


@router.get("/activity-timeline")
async def activity_timeline(db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    """Linha do tempo real do ambiente (incidente aberto, padrão aprendido,
    evento sinalizado) — o que aconteceu, em ordem, sem abrir 3 páginas."""
    return {"items": await build_activity_timeline(db)}


@router.get("/traffic-baseline")
async def traffic_baseline(db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    """Origens mais ativas nas últimas 24h comparadas ao próprio histórico de
    7 dias — pedido real: "trazer esses dados... sobre as informações e
    tráfego do ambiente"."""
    return {"items": await build_traffic_baseline_overview(db)}


@router.get("/learned-patterns")
async def learned_patterns(db: AsyncSession = Depends(get_db), _: User = Depends(current_user)) -> dict:
    """Lista (não só a contagem) dos padrões que a IA já confirmou o
    bastante pra virar via rápida — visibilidade de que a plataforma
    aprende de verdade com o volume recebido, não só reprocessa."""
    rows = (await db.execute(
        select(LearnedPattern).where(LearnedPattern.promoted.is_(True)).order_by(LearnedPattern.last_confirmed_at.desc())
    )).scalars().all()
    return {"items": [
        {
            "pattern_key": p.pattern_key, "mitre": p.mitre, "confirmations": p.confirmations,
            "first_confirmed_at": p.first_confirmed_at.isoformat(), "last_confirmed_at": p.last_confirmed_at.isoformat(),
            "recommendation": p.recommendation,
        }
        for p in rows
    ]}
