"""Mapa estático MITRE ATT&CK (tática -> técnicas) usado para cobertura e heat map,
mais o catálogo completo de técnicas (nome + descrição real) para dar
contexto de verdade num ticket — não só o ID.

Cobre as técnicas mais comuns em eventos Wazuh/Elastic; suficiente para o MVP —
ampliar conforme novas técnicas aparecerem nos eventos ingeridos.
"""
from __future__ import annotations

import json
from pathlib import Path

MITRE_TACTICS: list[dict] = [
    {"name": "Reconhecimento", "techniques": ["T1046", "T1595"]},
    {"name": "Acesso Inicial", "techniques": ["T1190", "T1133", "T1078", "T1110"]},
    {"name": "Execução", "techniques": ["T1059"]},
    {"name": "Persistência", "techniques": ["T1136", "T1098"]},
    {"name": "Escalação de Privilégio", "techniques": ["T1068"]},
    {"name": "Evasão de Defesa", "techniques": ["T1070", "T1027"]},
    {"name": "Movimento Lateral", "techniques": ["T1021", "T1570"]},
    {"name": "Exfiltração", "techniques": ["T1048", "T1071"]},
    {"name": "Impacto", "techniques": ["T1499", "T1486"]},
]

# Mapeamento classtype (Suricata) / category (ModSecurity-OWASP CRS) -> MITRE
# ATT&CK — não é dado inventado: `classtype` é a própria taxonomia do
# Suricata (ver `classification.config`, carregado por toda a comunidade
# ET-Open) e `category` vem do agrupamento OWASP CRS (sqli/rce/xss). A
# maioria das regras do ET-Open não embute `mitre_technique_id` na própria
# assinatura (só uma fração recente tem) — por isso esta tabela estática.
# Fonte única, usada tanto pelo fast-lane determinístico
# (skill_signature_match.py, casamento por SID/rule-id já relatado pela
# fonte) quanto pela unificação do catálogo de skills (skills_catalog.py,
# agrupando Suricata/ModSecurity por técnica ATT&CK). Só entram aqui
# classtypes com correspondência ATT&CK defensável e amplamente usada; os
# genéricos/vagos (misc-activity, bad-unknown, not-suspicious,
# targeted-activity, protocol-command-decode, misc-attack) ficam de fora —
# melhor sem técnica do que uma técnica forçada sem base real.
SURICATA_CLASSTYPE_TO_MITRE: dict[str, list[str]] = {
    "attempted-recon": ["T1595"],  # Active Scanning
    "network-scan": ["T1046"],  # Network Service Discovery
    "successful-recon-limited": ["T1595"],
    "trojan-activity": ["T1071"],  # Application Layer Protocol (C2)
    "command-and-control": ["T1071"],
    "attempted-admin": ["T1068"],  # Exploitation for Privilege Escalation
    "successful-admin": ["T1068"],
    "attempted-user": ["T1190"],  # Exploit Public-Facing Application
    "web-application-attack": ["T1190"],
    "shellcode-detect": ["T1203"],  # Exploitation for Client Execution
    "attempted-dos": ["T1499"],  # Endpoint Denial of Service
    "default-login-attempt": ["T1078"],  # Valid Accounts
    "suspicious-login": ["T1078"],
    "unsuccessful-user": ["T1110"],  # Brute Force
}

MODSECURITY_CATEGORY_TO_MITRE: dict[str, list[str]] = {
    "sqli": ["T1190"],  # Exploit Public-Facing Application
    "rce": ["T1190"],
    "xss": ["T1190"],
}


# Nome oficial (inglês) -> português das 15 táticas ATT&CK Enterprise que
# aparecem em `attack.json` (14 táticas "clássicas" + "Stealth", presente
# nesta versão da fonte) — cobertura completa, verificada contra o conjunto
# real de valores de `tactics` no bundle STIX baixado (nunca um valor
# "solto" sem tradução). Existe porque conteúdo de ticket/UI precisa ser
# obrigatoriamente em português — a tática vinha direto do STIX (inglês) sem
# isso, mesmo já existindo `MITRE_TACTICS` (só cobre uma amostra curada de
# técnicas para o heatmap, não as 222).
TACTIC_NAME_PT: dict[str, str] = {
    "Reconnaissance": "Reconhecimento",
    "Resource Development": "Desenvolvimento de Recursos",
    "Initial Access": "Acesso Inicial",
    "Execution": "Execução",
    "Persistence": "Persistência",
    "Privilege Escalation": "Escalação de Privilégio",
    "Defense Impairment": "Enfraquecimento de Defesas",
    "Defense Evasion": "Evasão de Defesa",
    "Stealth": "Furtividade",
    "Credential Access": "Acesso a Credenciais",
    "Discovery": "Descoberta",
    "Lateral Movement": "Movimento Lateral",
    "Collection": "Coleta",
    "Command and Control": "Comando e Controle",
    "Exfiltration": "Exfiltração",
    "Impact": "Impacto",
}

# Frase curta e correta em português por tática — troca a "primeira frase da
# descrição oficial" (inglês, do STIX) por uma explicação real do que a
# tática significa, autoral desta plataforma. Nível de tática, não de
# técnica individual: traduzir com confiança as 222 frases de descrição
# técnica (fonte STIX) uma a uma não é viável sem risco real de erro de
# tradução em conteúdo de segurança; a tática já dá contexto acionável
# (o "porquê" da técnica) sem esse risco.
TACTIC_DESCRIPTION_PT: dict[str, str] = {
    "Reconhecimento": "Coleta de informações sobre o ambiente-alvo antes de um ataque (varredura de rede, enumeração de serviços, etc.).",
    "Desenvolvimento de Recursos": "Preparação de infraestrutura ou recursos (servidores, contas, malware) para uso em etapas posteriores do ataque.",
    "Acesso Inicial": "Tentativa de obter o primeiro ponto de apoio dentro do ambiente-alvo.",
    "Execução": "Execução de código malicioso em um sistema local ou remoto.",
    "Persistência": "Manutenção de acesso ao ambiente mesmo após reinicializações, troca de credenciais ou outras interrupções.",
    "Escalação de Privilégio": "Obtenção de permissões de nível mais alto em um sistema ou rede.",
    "Enfraquecimento de Defesas": "Tentativa de evitar detecção ou desativar mecanismos de segurança.",
    "Evasão de Defesa": "Tentativa de evitar detecção ao longo de toda a operação.",
    "Furtividade": "Técnicas para permanecer não detectado durante a operação.",
    "Acesso a Credenciais": "Tentativa de obter credenciais de acesso (contas, senhas, chaves) de forma ilegítima.",
    "Descoberta": "Tentativa de mapear o ambiente interno (usuários, sistemas, rede) após obter acesso.",
    "Movimento Lateral": "Deslocamento entre sistemas dentro do ambiente para ampliar o alcance do ataque.",
    "Coleta": "Reunião de dados de interesse antes de uma possível exfiltração.",
    "Comando e Controle": "Comunicação com sistemas comprometidos para controlá-los remotamente.",
    "Exfiltração": "Extração não autorizada de dados do ambiente.",
    "Impacto": "Manipulação, interrupção ou destruição de sistemas e dados.",
}


def _load_technique_names_pt() -> dict[str, str]:
    """`skills_data/attack_pt.json` — tradução própria (não gerada por
    tradutor automático) do nome oficial de cada uma das 222 técnicas de
    `attack.json`, com cobertura 1:1 verificada (nenhuma técnica sem
    tradução, nenhuma tradução sem técnica correspondente)."""
    path = Path(__file__).parent.parent / "skills_data" / "attack_pt.json"
    return json.loads(path.read_text())


TECHNIQUE_NAME_PT: dict[str, str] = _load_technique_names_pt()


def normalize_to_parent_technique(technique_id: str) -> str:
    """Sigma referencia subtécnicas (ex.: "T1213.003"); nosso catálogo real
    (`attack.json`) só tem técnicas de nível superior (sem subtécnicas) —
    normaliza para a técnica pai ("T1213") para poder juntar com o catálogo
    que realmente temos, em vez de descartar a evidência."""
    return technique_id.split(".")[0]


def _load_technique_catalog() -> dict[str, dict]:
    """`skills_data/attack.json` — bundle STIX oficial do ATT&CK Enterprise
    (mesma fonte que `skills_catalog.py` usa para o RAG), 222 técnicas reais
    com nome/descrição/táticas. Reaproveitado aqui para dar definição de
    verdade num ticket (nome + primeira frase da descrição oficial), não só
    o ID cru "T1595"."""
    path = Path(__file__).parent.parent / "skills_data" / "attack.json"
    items = json.loads(path.read_text())
    return {it["id"]: it for it in items}


TECHNIQUE_CATALOG: dict[str, dict] = _load_technique_catalog()


def technique_tactic_pt(technique_id: str) -> str:
    """Tática (em português) da técnica, direto do catálogo real — cobre as
    222 técnicas de `attack.json`, não só a amostra curada de `MITRE_TACTICS`
    (usada só para o heatmap). "tática não catalogada" só para um ID que nem
    está no bundle STIX baixado (sub-técnica não normalizada, ou ID
    inválido)."""
    tech = TECHNIQUE_CATALOG.get(technique_id)
    if not tech or not tech.get("tactics"):
        return "tática não catalogada"
    return TACTIC_NAME_PT.get(tech["tactics"][0], tech["tactics"][0])


def describe_technique(technique_id: str) -> str:
    """'T1595 (Varredura Ativa) — tática: Reconhecimento — Coleta de
    informações sobre o ambiente-alvo antes de um ataque...' — cai para só o
    ID se a técnica não estiver no catálogo baixado (sub-técnica ou nova
    demais). Sempre em português (nome traduzido em `attack_pt.json`, tática
    traduzida em `TACTIC_NAME_PT`, frase autoral em `TACTIC_DESCRIPTION_PT`)
    — conteúdo de ticket precisa ser obrigatoriamente em português, nunca
    misturado com o inglês bruto do STIX original."""
    tech = TECHNIQUE_CATALOG.get(technique_id)
    if not tech:
        return technique_id
    name_pt = TECHNIQUE_NAME_PT.get(technique_id, tech["name"])
    tactics_pt = [TACTIC_NAME_PT.get(t, t) for t in (tech.get("tactics") or [])]
    parts = [f"{technique_id} ({name_pt})"]
    if tactics_pt:
        parts.append(f"tática: {', '.join(tactics_pt)}")
        description_pt = TACTIC_DESCRIPTION_PT.get(tactics_pt[0])
        if description_pt:
            parts.append(description_pt)
    return " — ".join(parts)
