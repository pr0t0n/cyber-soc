# Cyber SOC Copilot vs. Mercado de Agent SOC / SOCLess (2026)

Avaliação honesta da capacidade atual da plataforma (`cyber-soc`) contra o que
o mercado de "Agentic SOC" está realmente entregando em 2026 — não contra o
que o pitch deste projeto promete. Fontes de mercado citadas ao final.

**Correção de escopo (revisão desta análise):** esta plataforma **não é um
SOAR e não vai executar ação nenhuma** (não isola host, não desabilita
usuário, não bloqueia IP em firewall). O produto é: detectar → triar →
investigar → **informar** — via abertura de chamado (Jira/GLPI) ou
mensageria (Slack/Teams/e-mail). Isso não é uma limitação a esconder: é um
posicionamento de produto legítimo e comum em ambientes regulados/MSSP onde
a decisão de agir tem que ficar com um humano fora da ferramenta. A
comparação abaixo foi ajustada para não penalizar a ausência de execução de
resposta como se fosse um requisito — mas isso muda qual é o gap real (ver
seção 2 e 5).

---

## 1. O mercado agora usa um framework de avaliação, não só uma lista de features

A análise mais rigorosa disponível publicamente ([D3 Security, "12 Best
Agentic SOC Platforms in 2026"][d3]) parou de comparar "quantas integrações"
e passou a classificar plataformas em **4 arquiteturas** e **4 níveis de
autonomia em produção**, avaliados contra **8 critérios**. Isso é diretamente
aplicável aqui, então uso o mesmo framework em vez de inventar um novo.

### 4 arquiteturas de agente

| Arquitetura | O que é | Exemplo de mercado |
|---|---|---|
| Unified engine | Um único sistema de raciocínio, uma trilha de auditoria | D3 Morpheus |
| Multi-agent mesh | Agentes especializados coordenados por um orquestrador | Torq HyperAgents, Prophet Security, Conifers |
| Ecosystem-native | Embutido dentro da plataforma de um fabricante | CrowdStrike Charlotte AI, Microsoft Security Copilot |
| Focused analyst | Propósito único: triagem | Dropzone AI, Radiant Security, Simbian |

### 4 níveis de autonomia em produção (AL1–AL4)

| Nível | Definição |
|---|---|
| AL1 | Playbooks pré-escritos (SOAR clássico) |
| AL2 | IA assistida — o agente recomenda, o analista aprova |
| AL3 | IA conduz — o agente gera um plano, o analista revisa antes de executar |
| AL4 | Autonomia limitada — o agente executa dentro de guardrails de política |

### 8 critérios de avaliação

Arquitetura · teto de autonomia em produção · profundidade de investigação ·
amplitude/resiliência de integrações · trilha de auditoria · modelo de
playbook · estrutura de preço · suporte a multi-tenancy.

---

## 2. Onde a `cyber-soc` se encaixa

**Arquitetura**: mais próxima de **Focused analyst** (como Dropzone/Radiant/
Simbian) na via determinística, com um traço de **unified engine** no
Supervisor LangGraph que consolida 3 grupos especialistas num veredito único
e auditável. Não é **multi-agent mesh** de verdade — os "grupos"
(`attack_defend`/`network_signature`/`web_application`) são buscas RAG fixas
sobre catálogos estáticos, não agentes que decidem dinamicamente qual
ferramenta chamar em seguida. Não é **ecosystem-native** — não está embutida
em nenhum SIEM/EDR de fabricante, é standalone.

**Teto de autonomia real: AL1–AL2, e AL3/AL4 estão fora de escopo por
decisão de produto, não por limitação técnica.** A via rápida determinística
(`correlation_rules.py`, `skill_signature_match.py`) é honestamente mais
rigorosa que um SOAR AL1 comum, porque só confirma por fato objetivo (SID
catalogado, técnica MITRE já reportada, volume+reputação) — mas ainda é
lógica condicional pré-programada, não um agente planejando. O caminho LLM
(Supervisor) chega a AL2: recomenda em texto para um humano decidir. Como a
plataforma nunca vai executar ação de resposta (nem sob aprovação), AL3/AL4
simplesmente não se aplicam aqui — não é um degrau que falta subir, é um
teto definido pelo escopo do produto. **O que isso exige, e ainda não
existe, é que a recomendação em texto realmente chegue a alguém**: hoje
"bloquear o IP na borda" é uma string que só existe dentro do painel
Decisão/Evidência da própria plataforma — nenhum ticket é aberto, nenhuma
mensagem é enviada. Ver seção 5.

**Profundidade de investigação: rasa, unidimensional.** O documento de
arquitetura original desta própria pasta (seção 9, "Operação do N2
autônomo") descreve expansão investigativa real: hash→outros hosts,
IP→outras conexões, usuário→outros logins, processo→parent/child,
domínio→DNS histórico. **Nada disso existe.** A única correlação
implementada é "quantos eventos essa mesma origem gerou nos últimos 10
minutos" (`correlation.py`) — uma dimensão única. Prophet Security e
Simbian, por comparação, descrevem investigação que "puxa dados de pacote,
consulta o SIEM, verifica logs de identidade e reconstrói o que aconteceu"
([Simbian][simbian]) — um loop de ferramentas dinâmico, não uma janela fixa
de 10 minutos numa única tabela.

**Amplitude de integrações: 1.** Wazuh é a única fonte real, viva, testada
ponta a ponta nesta sessão (agente nativo + Suricata real + skill-matching
determinístico). Elastic tem tradutor de schema mas nunca foi testado contra
um Elasticsearch real. "Generic" é um schema próprio, não uma integração.
Mercado: Dropzone AI declara 90+ integrações, Prophet 80+, D3 Morpheus 800+,
CrowdStrike Charlotte ~150 ([D3 Security][d3]). Essa é a distância mais
gritante entre esta plataforma e qualquer concorrente citado.

**Trilha de auditoria: ponto forte real.** Cada evento carrega
`rules_engine_verdict` completo — quais grupos rodaram, se casaram, se foi
determinístico ou julgamento de LLM, candidatos considerados, motivo da
degradação quando o Ollama cai. Isso é genuinamente visível na UI (painel
Decisão/Evidência da página Análises) e é mais transparente que a maioria
dos "recommendation-only" que o mercado critica abertamente (Simbian: "AI
SOC stories [que] terminam numa recomendação").

**Resposta automatizada: fora de escopo por decisão de produto — e por isso
não entra na comparação de "gap".** O critério mais citado pelo mercado
2026 ("o agente age — contenção, revogação de identidade, mudança de
firewall — sob guardrails", [Simbian][simbian]) mede um tipo de produto que
esta plataforma explicitamente não é. As seções 13–16 do documento de
arquitetura original (Response Orchestration, Policy Engine, Kill Switch)
descrevem esse modelo — e por essa correção de escopo, devem ser tratadas
como **não aplicáveis**, não como pendência.

**O que É gap real dentro do escopo correto (notificar, não agir): o
dispatcher de chamado/mensageria não existe.** `Connector` já tem os tipos
`jira`/`glpi`/`slack`/`teams`/`webhook`/`email` com schema de credencial
real (`connector_schemas.py`, construído nesta sessão) — mas **nenhum
código chama essas integrações**. Busquei no repositório inteiro por
qualquer função que abra um chamado ou envie uma mensagem quando um
incidente é criado (`_open_or_fuse_incident` em `rules_engine.py`) e não
existe nenhuma — a integração para no CRUD de credencial. O próprio
`README.md` do projeto já documentava isso antes desta análise ("`connectors`
já tem os tipos; falta o dispatcher de notificação/ticket"). Para um produto
cujo valor final é "informar", isso não é um gap secundário — é o último
passo do fluxo principal, sem o qual um incidente confirmado morre dentro da
própria UI.

**Multi-tenancy: cosmética.** Existe uma tag de cliente por conector
(`client_tag`) que filtra o dashboard — não é isolamento real de dados por
tenant, RBAC por tenant, nem nada parecido com o que Conifers CognitiveSOC
chama de "multi-tenancy nativa" para MSSPs.

**Threat Hunting, Detection Engineering (replay/CI), Feedback Loop
TP/FP→tuning de regra: nenhum implementado.** Todos descritos em detalhe no
documento de arquitetura original (seções 18–22), nenhum com código
correspondente.

---

## 3. Onde a plataforma é honestamente competitiva (não é só fraqueza)

- **Velocidade da via determinística**: milissegundos a poucos segundos do
  recebimento ao veredito para os casos objetivos (assinatura catalogada,
  correlação com evidência quantitativa) — medido ao vivo nesta sessão
  (evento recebido `18:02:26.521` → analisado `18:02:29.506`). Isso bate de
  frente com a reivindicação central de TODA a categoria "AI SOC analyst"
  (velocidade + cobertura de triagem), com a vantagem de que aqui a rapidez
  vem de **fato verificável** (SID real, correlação real), não de um LLM
  respondendo rápido e errado.
- **NIDS de verdade, não simulado**: Suricata real com ruleset ET-Open real
  (68 mil+ regras via `suricata-update`, não uma amostra decorativa),
  gerando alertas genuínos que passam pelo pipeline completo. A maioria dos
  "AI SOC" citados acima são camadas de triagem sobre SIEM/EDR de terceiros
  — não trazem sensor de rede próprio nenhum.
- **Honestidade sobre degradação**: o sistema marca explicitamente quando um
  veredito é "degradado" (RAG ou LLM indisponível) em vez de fingir uma
  conclusão. Isso é mais raro do que deveria ser no mercado.
- **Sem alucinação de dado**: catálogos de skill (ATT&CK, D3FEND, Suricata,
  ModSecurity, Sigma) são baixados de fontes reais, não gerados por LLM —
  princípio consistente desde o início do projeto (`skills_catalog.py`) e
  reforçado nesta sessão com o matching determinístico por SID/ID real.

---

## 4. Tabela-resumo (framework D3 aplicado a esta plataforma)

| Critério | Cyber SOC Copilot hoje | Referência de mercado 2026 |
|---|---|---|
| Arquitetura | Focused analyst + traço de unified engine | 4 categorias definidas, mercado maduro em todas |
| Teto de autonomia | AL1–AL2 (teto definido por escopo, não limitação) | AL3–AL4 padrão nos players "SOAR-like"; irrelevante para players "notify-only" |
| Fechamento do loop (chamado/mensageria) | **Não implementado** — credencial existe, dispatcher não | Presente nos players ITSM-first (ex.: Inopli, ver doc de mercado anterior) |
| Profundidade de investigação | 1 dimensão (correlação por IP/10min) | Multi-hop, multi-fonte, dinâmico |
| Integrações de coleta | 1 viva (Wazuh) + 1 schema não testado (Elastic) | 80–800+ |
| Trilha de auditoria | Forte e honesta | Variável — ponto de venda para poucos |
| Multi-tenancy | Cosmética (tag) | Nativa em players MSSP-focused |
| Threat hunting / Detection Eng. / Feedback loop | Nenhum | Presente em players maduros |
| Execução de resposta (SOAR) | **Fora de escopo por decisão de produto** | Padrão nos "Agentic SOC" citados — categoria diferente da nossa |

---

## 5. Se fosse priorizar 3 investimentos, seriam estes

1. **O dispatcher de notificação/ticket — este é o único item desta lista
   que bloqueia o próprio propósito declarado do produto.** Um serviço
   (`services/notify.py` ou similar) chamado de dentro de
   `_open_or_fuse_incident` (`rules_engine.py`) tanto no ramo que cria um
   incidente novo quanto no que escala um existente, que: (a) para
   conectores `notification` habilitados, monta a mensagem (código, título,
   severidade, risk_score, recomendação, link para o evento) e (b) despacha
   via webhook simples primeiro (Slack/Teams — só precisa de uma URL, sem
   OAuth), depois Jira/GLPI (REST real, formato já documentado nos
   schemas). Sem isso, "informar por chamado/mensageria" é uma promessa da
   UI de Integrações, não um comportamento do sistema.
2. **Segunda integração de coleta viva de verdade** (Elastic testado ponta
   a ponta contra um cluster real, não só o tradutor de schema) — sem isso,
   "SIEM agnóstico" continua sendo uma alegação, não um fato.
3. **Correlação multi-hop mínima** — pelo menos IP→outros eventos do mesmo
   IP em janelas maiores, e hash→outros hosts quando o dado existir — para
   sair de "1 dimensão" e melhorar a qualidade do que vai DENTRO do
   chamado/mensagem que o item 1 vai enviar (a mensagem só é tão boa quanto
   a investigação por trás dela).

---

## Fontes de mercado consultadas

- [D3 Security — "The 12 Best Agentic SOC Platforms in 2026: Architectures, Autonomy Levels, and a Full Comparison"](https://d3security.com/blog/best-agentic-soc-platforms/)
- [Simbian — "Top AI SOC Platforms in 2026: The 4 Capabilities That Actually Matter"](https://simbian.ai/blog/top-ai-soc-platforms-2026)
- [Prophet Security — "Top 5 AI SOC Analyst Platforms of 2026"](https://www.prophetsecurity.ai/blog/top-5-ai-soc-analyst-platforms)

Documentos internos usados como base de comparação:
`socless_n1_n2_arquitetura_regras_operacao.md` (arquitetura-alvo) e
`plataformas-socless-analise.md` (Inopli/Mayko/Lumu, geração anterior de
mercado).

[d3]: https://d3security.com/blog/best-agentic-soc-platforms/
[simbian]: https://simbian.ai/blog/top-ai-soc-platforms-2026
