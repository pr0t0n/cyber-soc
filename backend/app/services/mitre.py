"""Mapa estático MITRE ATT&CK (tática -> técnicas) usado para cobertura e heat map.

Cobre as técnicas mais comuns em eventos Wazuh/Elastic; suficiente para o MVP —
ampliar conforme novas técnicas aparecerem nos eventos ingeridos.
"""

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

TACTIC_BY_TECHNIQUE: dict[str, str] = {
    tech: tactic["name"] for tactic in MITRE_TACTICS for tech in tactic["techniques"]
}
