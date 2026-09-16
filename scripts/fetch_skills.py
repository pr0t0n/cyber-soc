"""Reproduz backend/app/skills_data/*.json a partir das fontes públicas reais.

Não roda automaticamente (a app usa os JSONs já commitados) — é para quando
alguém quiser atualizar o catálogo. Sem chave de API, sem mock: baixa os
arquivos originais e extrai só os campos usados como skill.

    python scripts/fetch_skills.py
"""
from __future__ import annotations

import json
import re
import subprocess
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

OUT_DIR = Path(__file__).parent.parent / "backend" / "app" / "skills_data"


def _github_token() -> str | None:
    """GITHUB_TOKEN no ambiente (ex.: passado ao container) tem prioridade;
    senão reusa a credencial HTTPS do git já configurada na máquina — evita o
    rate limit de 60 req/h da API do GitHub sem autenticação. Nunca grava em disco."""
    import os

    if env_token := os.environ.get("GITHUB_TOKEN"):
        return env_token
    try:
        out = subprocess.run(
            ["git", "credential", "fill"], input="protocol=https\nhost=github.com\n",
            capture_output=True, text=True, timeout=10,
        ).stdout
        for line in out.splitlines():
            if line.startswith("password="):
                return line.split("=", 1)[1]
    except Exception:  # noqa: BLE001
        pass
    return None


def _get_json_authed(url: str) -> dict:
    token = _github_token()
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"} if token else {})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())

ATTACK_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
D3FEND_URL = "https://d3fend.mitre.org/ontologies/d3fend.json"
SURICATA_URLS = {
    "scan": "https://rules.emergingthreats.net/open/suricata-7.0.3/rules/emerging-scan.rules",
    "malware": "https://rules.emergingthreats.net/open/suricata-7.0.3/rules/emerging-malware.rules",
    "exploit": "https://rules.emergingthreats.net/open/suricata-7.0.3/rules/emerging-exploit.rules",
}
CRS_URLS = {
    "xss": "https://raw.githubusercontent.com/coreruleset/coreruleset/main/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf",
    "sqli": "https://raw.githubusercontent.com/coreruleset/coreruleset/main/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
    "rce": "https://raw.githubusercontent.com/coreruleset/coreruleset/main/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf",
}
# Emerging Threats tem dezenas de milhares de regras (malware/exploit); uma
# amostra real (não o feed inteiro) mantém o catálogo em tamanho de repositório.
SAMPLE_LIMIT = {"scan": None, "malware": 150, "exploit": 150}


def _get(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as r:  # noqa: S310 - URLs fixas acima, não input externo
        return r.read()


def fetch_attack() -> list[dict]:
    data = json.loads(_get(ATTACK_URL))
    objs = data["objects"]
    tactics_by_shortname = {t["x_mitre_shortname"]: t["name"] for t in objs if t["type"] == "x-mitre-tactic"}
    patterns = [o for o in objs if o["type"] == "attack-pattern" and not o.get("revoked") and not o.get("x_mitre_deprecated")]

    def tid(o):
        for ref in o.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id")
        return None

    out = []
    for o in patterns:
        t = tid(o)
        if not t or "." in t:  # só técnicas de nível superior, sem subtécnicas
            continue
        tactics = sorted({tactics_by_shortname.get(p["phase_name"], p["phase_name"]) for p in o.get("kill_chain_phases", [])})
        desc = re.sub(r"\s+", " ", (o.get("description") or "").split("\n\n")[0].strip())[:600]
        out.append({"id": t, "name": o["name"], "tactics": tactics, "platforms": o.get("x_mitre_platforms", []), "description": desc})
    out.sort(key=lambda x: x["id"])
    return out


def fetch_d3fend() -> dict[str, list[dict]]:
    data = json.loads(_get(D3FEND_URL))
    graph = data["@graph"]
    by_id = {n["@id"]: n for n in graph if "@id" in n}
    roots = {"d3f:Harden", "d3f:Detect", "d3f:Isolate", "d3f:Deceive", "d3f:Evict", "d3f:Model"}

    def rid(v):
        return v.get("@id") if isinstance(v, dict) else None

    def type_list(n):
        t = n.get("@type")
        return t if isinstance(t, list) else [t]

    def parents(n):
        sub = n.get("rdfs:subClassOf")
        items = sub if isinstance(sub, list) else ([sub] if sub else [])
        return [pid for it in items if (pid := rid(it)) and pid in by_id and "owl:Restriction" not in type_list(by_id[pid])]

    def root_of(node_id, seen=None):
        seen = seen or set()
        if node_id in seen or node_id not in by_id:
            return None
        seen.add(node_id)
        if node_id in roots:
            return node_id
        n = by_id[node_id]
        enables = rid(n.get("d3f:enables"))
        if enables in roots:
            return enables
        if enables and (r := root_of(enables, seen)):
            return r
        for p in parents(n):
            if r := root_of(p, seen):
                return r
        return None

    catalog: dict[str, list[dict]] = {}
    for n in graph:
        nid = n.get("@id", "")
        if not nid.startswith("d3f:") or "owl:Class" not in type_list(n):
            continue
        if nid in roots or not n.get("d3f:definition") or not n.get("rdfs:label"):
            continue
        if re.match(r"^d3f:(T\d|AML|TA\d|M\d)", nid):
            continue
        r = root_of(nid)
        if r:
            catalog.setdefault(r, []).append({
                "id": n.get("d3f:d3fend-id", nid.split(":", 1)[1]),
                "name": n["rdfs:label"],
                "definition": re.sub(r"\s+", " ", n["d3f:definition"]).strip()[:500],
            })
    return catalog


def fetch_suricata() -> list[dict]:
    out = []
    for _category, url in SURICATA_URLS.items():
        limit = SAMPLE_LIMIT[_category]
        text = _get(url).decode("utf-8", errors="ignore")
        count = 0
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m_sid = re.search(r"\bsid\s*:\s*(\d+)", line)
            m_msg = re.search(r'\bmsg\s*:\s*"([^"]*)"', line)
            if not (m_sid and m_msg):
                continue
            m_class = re.search(r"\bclasstype\s*:\s*([\w-]+)", line)
            m_rev = re.search(r"\brev\s*:\s*(\d+)", line)
            m_proto = re.match(r"(alert|drop|reject|pass)\s+(\S+)\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)", line)
            out.append({
                "sid": m_sid.group(1), "msg": m_msg.group(1),
                "classtype": m_class.group(1) if m_class else None,
                "rev": m_rev.group(1) if m_rev else None,
                "action": m_proto.group(1) if m_proto else None,
                "protocol": m_proto.group(2) if m_proto else None,
                "direction": f"{m_proto.group(3)}:{m_proto.group(4)} {m_proto.group(5)} {m_proto.group(6)}:{m_proto.group(7)}" if m_proto else None,
            })
            count += 1
            if limit and count >= limit:
                break
    return out


def fetch_modsecurity() -> list[dict]:
    out = []
    for category, url in CRS_URLS.items():
        content = re.sub(r"\\\n\s*", " ", _get(url).decode("utf-8", errors="ignore"))
        for line in content.splitlines():
            line = line.strip()
            if not line.startswith("SecRule") and not line.startswith("SecAction"):
                continue
            m_id = re.search(r"\bid\s*:\s*'?(\d+)'?", line)
            if not m_id:
                continue
            m_msg = re.search(r"\bmsg\s*:\s*'([^']*)'", line)
            if not m_msg:
                continue
            out.append({
                "id": m_id.group(1), "msg": m_msg.group(1),
                "tags": re.findall(r"\btag\s*:\s*'([^']*)'", line),
                "severity": (m := re.search(r"\bseverity\s*:\s*'?([\w-]+)'?", line)) and m.group(1),
                "category": category,
            })
    return out


SIGMA_LEVEL_MAP = {"informational": "info", "low": "baixa", "medium": "media", "high": "alta", "critical": "critica"}
_SIGMA_CATEGORY_CAP = 60  # SigmaHQ tem >3000 regras; uma amostra real por categoria mantém o repo leve.


def _sigma_entry(raw_yaml: str, source: str) -> dict | None:
    try:
        doc = yaml.safe_load(raw_yaml)
    except yaml.YAMLError:
        return None
    if not isinstance(doc, dict) or not doc.get("title"):
        return None
    tags = doc.get("tags") or []
    mitre = sorted({t.split(".", 1)[1].upper() for t in tags if t.startswith("attack.t")})
    logsource = doc.get("logsource") or {}
    return {
        "id": doc.get("id") or doc.get("title"),
        "title": doc["title"],
        "description": re.sub(r"\s+", " ", (doc.get("description") or "")).strip()[:500],
        "level": SIGMA_LEVEL_MAP.get(str(doc.get("level", "")).lower(), "media"),
        "logsource": {k: v for k, v in logsource.items() if k in ("category", "product", "service")},
        "mitre": mitre,
        "source_repo": source,
    }


def fetch_sigma() -> list[dict]:
    out: list[dict] = []

    # 1) SigmaHQ oficial — amostra real por categoria (rules/windows, cloud, linux, ...)
    tree = _get_json_authed("https://api.github.com/repos/SigmaHQ/sigma/git/trees/master?recursive=1")
    paths_by_cat: dict[str, list[str]] = {}
    for node in tree["tree"]:
        p = node["path"]
        if p.startswith("rules/") and p.endswith((".yml", ".yaml")):
            cat = p.split("/")[1]
            bucket = paths_by_cat.setdefault(cat, [])
            if len(bucket) < _SIGMA_CATEGORY_CAP:
                bucket.append(p)
    selected = [p for bucket in paths_by_cat.values() for p in bucket]

    def _fetch_sigma_path(path: str) -> dict | None:
        try:
            raw = _get(f"https://raw.githubusercontent.com/SigmaHQ/sigma/master/{path}").decode("utf-8", "ignore")
        except Exception:  # noqa: BLE001
            return None
        return _sigma_entry(raw, "SigmaHQ/sigma")

    with ThreadPoolExecutor(max_workers=12) as pool:
        for entry in pool.map(_fetch_sigma_path, selected):
            if entry:
                out.append(entry)

    # 2) SIEM-Content (abdulmyid-cyber) — regras "zero-day" recentes, repo pequeno, pega tudo.
    items = _get_json_authed("https://api.github.com/repos/abdulmyid-cyber/SIEM-Content/contents/")
    yml_names = [i["name"] for i in items if i["type"] == "file" and i["name"].endswith((".yml", ".yaml"))]
    for name in yml_names:
        try:
            raw = _get(f"https://raw.githubusercontent.com/abdulmyid-cyber/SIEM-Content/main/{urllib.parse.quote(name)}").decode("utf-8", "ignore")
        except Exception:  # noqa: BLE001
            continue
        entry = _sigma_entry(raw, "abdulmyid-cyber/SIEM-Content")
        if entry:
            out.append(entry)
    return out


_ATR_CATEGORY_CAP = 12  # cada regra ATR é rica (referências OWASP/MITRE ATLAS/CVE/compliance) — amostra por categoria


def fetch_agent_threats() -> list[dict]:
    out: list[dict] = []
    categories = _get_json_authed("https://api.github.com/repos/Agent-Threat-Rule/agent-threat-rules/contents/rules")
    for cat in categories:
        if cat["type"] != "dir":
            continue
        files = _get_json_authed(cat["url"])
        yml_files = [f["name"] for f in files if f["name"].endswith((".yml", ".yaml"))][:_ATR_CATEGORY_CAP]

        def _fetch_atr(name: str, category: str = cat["name"]) -> dict | None:
            try:
                raw = _get(f"https://raw.githubusercontent.com/Agent-Threat-Rule/agent-threat-rules/main/rules/{category}/{name}").decode("utf-8", "ignore")
                doc = yaml.safe_load(raw)
            except Exception:  # noqa: BLE001
                return None
            if not isinstance(doc, dict) or not doc.get("id"):
                return None
            refs = doc.get("references") or {}
            return {
                "id": doc["id"],
                "title": doc.get("title") or doc["id"],
                "description": re.sub(r"\s+", " ", (doc.get("description") or "")).strip()[:500],
                "severity": doc.get("severity", "media"),
                "category": category,
                "owasp_llm": refs.get("owasp_llm") or [],
                "owasp_agentic": refs.get("owasp_agentic") or [],
                "mitre_atlas": refs.get("mitre_atlas") or [],
                "cve": refs.get("cve") or [],
            }

        with ThreadPoolExecutor(max_workers=8) as pool:
            for entry in pool.map(_fetch_atr, yml_files):
                if entry:
                    out.append(entry)
    return out


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print("Baixando MITRE ATT&CK (STIX bundle oficial)...")
    (OUT_DIR / "attack.json").write_text(json.dumps(fetch_attack(), indent=1))
    print("Baixando MITRE D3FEND (ontologia oficial)...")
    (OUT_DIR / "d3fend.json").write_text(json.dumps(fetch_d3fend(), indent=1))
    print("Baixando Suricata (Emerging Threats Open Ruleset)...")
    (OUT_DIR / "suricata.json").write_text(json.dumps(fetch_suricata(), indent=1))
    print("Baixando ModSecurity (OWASP Core Rule Set)...")
    (OUT_DIR / "modsecurity.json").write_text(json.dumps(fetch_modsecurity(), indent=1))
    print("Baixando Sigma (SigmaHQ oficial + abdulmyid-cyber/SIEM-Content)...")
    (OUT_DIR / "sigma.json").write_text(json.dumps(fetch_sigma(), indent=1))
    print("Baixando Agent Threat Rules (Agent-Threat-Rule/agent-threat-rules)...")
    (OUT_DIR / "agent_threats.json").write_text(json.dumps(fetch_agent_threats(), indent=1))
    print("Pronto — reinicie a API (ou apague a tabela skills) para recarregar o bootstrap.")


if __name__ == "__main__":
    main()
