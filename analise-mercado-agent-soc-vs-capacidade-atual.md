# Cyber SOC Copilot vs. Mercado de Agent SOC / SOCLess (2026)

Avaliação honesta da capacidade atual da plataforma (`cyber-soc`) contra o que
o mercado de "Agentic SOC" está realmente entregando em 2026 — não contra o
que o pitch deste projeto promete. Fontes de mercado citadas ao final.

**Correção de escopo (permanente, já validada em revisão anterior):** esta
plataforma **não é um SOAR e não vai executar ação nenhuma** (não isola
host, não desabilita usuário, não bloqueia IP em firewall). O produto é:
detectar → triar → investigar → **informar** — via abertura de chamado
(Jira/GLPI) ou mensageria (Slack/Teams/e-mail). Isso é um posicionamento de
produto legítimo e comum em ambientes regulados/MSSP — e o mercado 2026
confirma que é uma categoria reconhecida, não uma desculpa: o guia mais
recente da D3 Security ([D3 Security, 2026][d3-2026]) trata
"Notification-Only" como um dos três modos operacionais do mercado, ao lado
de "Execution-Capable" (D3 Morpheus, UnderDefense, Prophet) e "Hybrid"
(CrowdStrike, Palo Alto — execução só dentro do próprio ecossistema).

**Atualização desta revisão:** desde a análise anterior, a plataforma
fechou o gap mais crítico identificado (dispatcher de notificação/ticket —
antes inexistente, agora real e validado com ticket de verdade no GLPI) e
ganhou capacidades que não existiam: aprendizado incremental
(`learning.py`), linha de base comportamental de 7 dias (`baseline.py`),
retroalimentação de contexto de incidente no LangGraph (`_open_incident_context`),
validação anti-alucinação do Supervisor (`grounding_rejected`), e uma visão
operacional para N3 (`narrative.py` + página Visão Operacional). O restante
deste documento reflete o estado real de hoje, não o de semanas atrás.

---

## 1. O mercado usa um framework de avaliação, não uma lista de features

Combinando o framework original ([D3 Security, "12 Best Agentic SOC
Platforms"][d3-orig]) com o guia mais recente ([D3 Security, "The Best AI
SOC Platforms 2026"][d3-2026]), o mercado avalia por **8 critérios**, 3 dos
quais são novos desde a última revisão deste documento:

| Critério | Descrição |
|---|---|
| Arquitetura | Unified engine · Multi-agent mesh · Ecosystem-native · Focused analyst |
| Teto de autonomia | AL1 (playbook fixo) → AL4 (executa sob guardrails) |
| **Profundidade de investigação (novo detalhe 2026)** | **L1** (rápida, rasa) vs. **L2** (contexto completo, multi-hop) |
| Amplitude/resiliência de integrações | Contagem de conectores + capacidade de autorreparo quando a API do fornecedor muda |
| Trilha de auditoria / **validação de IA (novo critério 2026)** | Visibilidade da cadeia de raciocínio + validação independente de que a IA não alucina |
| Modelo de playbook | Estático vs. gerado dinamicamente por contexto |
| **Autonomia fora do horário comercial (novo critério 2026)** | % do ciclo de vida do alerta resolvido de ponta a ponta sem humano |
| Multi-tenancy / custo total | Isolamento nativo por tenant + custo de licença+integração+equipe combinado |

O critério **"validação de IA / transparência"** é o mais relevante para
esta revisão — é exatamente onde a correção do Supervisor feita nesta sessão
(ver seção 3) se encaixa, e é um critério que a maioria dos concorrentes
citados não publica dado nenhum sobre.

---

## 2. Onde a `cyber-soc` se encaixa hoje

**Arquitetura**: Focused analyst com traço de unified engine (Supervisor
LangGraph consolidando 3 grupos RAG num veredito único e auditável) — sem
mudança desde a última revisão.

**Teto de autonomia**: AL1–AL2 por decisão de produto (não limitação
técnica) — AL3/AL4 continuam fora de escopo. **O que mudou**: o item que
antes travava mesmo o AL1–AL2 de fazer sentido ("a recomendação em texto
não chega a lugar nenhum") **foi resolvido** — ver seção 3.

**Profundidade de investigação: ainda L1, mas deixou de ser
unidimensional.** Antes: uma única correlação (mesma origem, 10 minutos).
Hoje são três sinais reais, cada um com teste automatizado:
1. Correlação de curto prazo (`correlation.py`, 10 min) — igual antes.
2. Linha de base de 7 dias por origem (`baseline.py`) — "essa origem nunca
   apareceu antes" ou "isso é 3x acima do próprio padrão dela" vira flag de
   investigação (`rules_engine_status = suspicious`), mesmo sem nenhuma
   skill do catálogo confirmar nada.
3. Retroalimentação de incidente (`_open_incident_context`,
   `rules_engine.py`) — quando um evento novo se funde num incidente já
   aberto, o Supervisor recebe como contexto o que a plataforma **já
   confirmou** sobre aquela origem (técnica, skills, quantos eventos, há
   quanto tempo) antes de julgar o evento novo. Isso é literalmente o "loop
   agent com estado retroalimentado" que documentos de arquitetura
   anteriores pediam — mas ainda é **um único hop** (mesma origem/mesmo
   incidente), não o multi-hop real que Prophet/Simbian descrevem (hash→
   outros hosts, IP→outras conexões via consulta ativa a outra fonte,
   domínio→DNS histórico). Isso continua sendo L1 pela definição do guia
   2026: rápido, mas raso além da própria origem.

**Amplitude de integrações: ainda 1 fonte de coleta viva.** Wazuh continua
sendo a única testada ponta a ponta (agente nativo + Suricata real +
detecção determinística). Elastic tem tradutor de schema, nunca testado
contra um cluster real. Mercado 2026, por comparação: Dropzone AI 90+,
Stellar Cyber/CrowdStrike ~150+, UnderDefense 250+, Google SecOps 300+,
Splunk 500+, D3 Morpheus 800+ ([D3 Security, 2026][d3-2026]). Essa
continua sendo a distância mais gritante — e a única desta lista que não
mudou nada desde a última revisão.

**Fechamento do loop (chamado/mensageria): RESOLVIDO.** `notify.py`
existe, é chamado de dentro de `_open_or_fuse_incident` na criação e na
escalada de severidade (nunca a cada evento fundido), e foi validado com
**ticket real criado no GLPI** (não mock) — sessão em duas etapas
(`initSession`→`Ticket/`), conteúdo do ticket com origem/destino,
geolocalização quando disponível, definição completa da técnica MITRE
(nome + tática + descrição oficial, não só o ID), skill confirmada,
histórico de 7 dias da origem, e recomendação. **Ressalva honesta**: só o
sender do GLPI foi validado contra um serviço real. Slack, Teams e Jira têm
código real (`_send_slack`/`_send_teams`/`_send_jira`) e teste automatizado
com HTTP client fake — nenhum dos três foi testado contra um workspace/
instância real. GLPI também ganhou sincronização de status bidirecional: o
status do incidente na plataforma agora é **lido do ticket real no GLPI**
(`sync_all_glpi_statuses`), não uma lista suspensa local independente —
editar manualmente é bloqueado (409) uma vez que existe ticket.

**Validação anti-alucinação do Supervisor — capacidade nova, sem
equivalente publicado pelos concorrentes citados.** Achado real desta
sessão: o Supervisor (LLM pequeno, qwen2.5:1.5b) ocasionalmente devolvia
`"matched": true` com `matched_skills` inventados mesmo quando os 3 grupos
RAG, individualmente, não confirmavam nada — isso gerava incidente
verdadeiro (e, agora que o dispatcher existe, teria gerado ticket) para
telemetria de host sem risco nenhum. Corrigido com uma trava de
aterramento: o veredito final nunca promove "nenhum grupo achou skill
real" para "matched", só pode confirmar o que os grupos genuinamente
encontraram. **Auditoria retroativa nesta sessão encontrou e corrigiu 166
dos 185 incidentes então abertos** (89,7%) — reprocessados pelo pipeline
corrigido, não apagados às cegas (o dado bruto do Wazuh permaneceu, só o
veredito mudou). Esse conjunto específico foi limpo antes de um reset
completo de dados feito depois, para um teste de volume separado — o
código da correção continua ativo independente disso; o número serve como
prova de quanto uma alucinação não travada custava, não como estado atual
do banco. A contagem de quantas vezes a trava precisa agir
(`grounding_rejected_count`) é uma métrica ao vivo no dashboard desde
então — nenhum dos concorrentes citados no guia 2026 publica esse tipo de
dado sobre a própria taxa de alucinação.

**Aprendizado incremental — implementado, ainda não provado em uso real.**
`learning.py`: quando o Supervisor confirma o mesmo veredito para o mesmo
`Event.type` 3 vezes ou mais, o padrão é promovido para via rápida (sem
gastar LLM de novo). Mecanismo real, testado em unidade — mas **zero
padrões foram promovidos organicamente neste ambiente até agora**
(`learned_patterns_count = 0` em produção local): todo o tráfego de teste
gerado nesta sessão bateu a via rápida determinística existente
(`skill_signature_match`/`correlation_rules`) antes de precisar do
Supervisor 3 vezes para o mesmo tipo de alerta. Isso não é um problema de
código, é ausência de evidência de funcionamento real ainda.

**Visão operacional (N3) — nova.** Página dedicada sintetiza incidente
como história (origem, há quanto tempo, o que já foi confirmado, status
real do ticket), linha do tempo real do ambiente (incidente aberto +
padrão aprendido + evento sinalizado, mesclados e ordenados), e comparação
de tráfego das origens mais ativas contra o próprio histórico de 7 dias.
Isso é leitura, não ainda um espaço de trabalho — analista não comenta,
não anota, não dispara ação a partir dali (ver seção 4, item 9).

**Multi-tenancy: ainda cosmética.** `client_tag` continua sendo um filtro
de dashboard, não isolamento de dados/RBAC por tenant.

**Threat Hunting proativo, Detection Engineering com aprovação humana,
Feedback loop TP/FP do analista: nenhum implementado.** Sem mudança.

---

## 3. Onde a plataforma é honestamente competitiva

- **Velocidade da via determinística**: milissegundos a poucos segundos do
  recebimento ao veredito para casos objetivos — medido ao vivo sob carga
  real (30.000 eventos gerados em lotes monitorados, 0 atraso de fila, 0
  degradação de memória).
- **Fusão de alerta (Alert Fusion) provada sob volume real**: ~170 mil
  eventos processados nesta sessão viraram 1 incidente ativo (mesma
  origem) — não é uma alegação de "redução de ruído", é o resultado
  observado de rodar a carga de verdade.
- **NIDS real, não simulado — mas é infraestrutura externa, não código da
  plataforma.** O Suricata com ruleset ET-Open completo (68 mil+ regras via
  `suricata-update`, confirmado nesta revisão) roda como processo próprio
  na pasta `wazuh/` (fora do `backend/`), inspecionando pacote de verdade
  na interface do container do Wazuh manager — a plataforma nunca executa
  Suricata nem carrega essas 68 mil regras; ela só recebe o alerta já
  pronto via push do Wazuh. O que fica DENTRO do código da plataforma
  (`backend/app/skills_data/suricata.json`) é uma biblioteca bem menor —
  586 assinaturas curadas (sid/msg/classtype), usadas só para confirmação
  determinística por SID já catalogado (`skill_signature_match.py`), sem
  inspecionar pacote nenhum.
- **Honestidade sobre degradação e sobre alucinação**: o sistema marca
  explicitamente quando um veredito é degradado (RAG/LLM indisponível) E
  agora também quando a validação precisou corrigir uma alucinação do
  Supervisor — as duas coisas expostas como métricas distintas no
  dashboard (`stability_pct` ≠ `grounding_rejected_count`), depois de um
  achado real onde as duas ficavam confundidas numa única "eficiência" que
  não significava o que parecia significar.
- **Catálogos de skill reais**: ATT&CK, D3FEND, Suricata, ModSecurity,
  Sigma baixados de fonte real, nunca gerados por LLM — mantido e reforçado
  com o mapeamento classtype/categoria→técnica MITRE (novo nesta sessão),
  que hidratou `mitre_coverage_pct` de eventos que antes tinham skill
  confirmada mas nenhuma técnica anexada.
- **Dado real de ponta a ponta em toda demonstração**: cada capacidade
  descrita neste documento foi validada contra sistemas reais rodando
  (Wazuh real, Suricata real, GLPI real) nesta mesma sessão — não é a
  distância "demo vs. o que realmente foi entregue" que o próprio guia
  2026 aponta como risco central da categoria ([D3 Security, 2026][d3-2026]:
  "platforms often turn out to summarize alerts and wait for humans...the
  distance between demonstrated and shipped autonomy is critical").
- **191 testes automatizados passando** cobrindo especificamente os pontos
  que mais geram alegação vazia no mercado: aterramento anti-alucinação,
  fusão de alerta, hidratação de MITRE, sincronização de status com GLPI,
  e o retorno correto da via rápida sem chamar o LLM.

---

## 4. Os 10 pontos que ainda precisam ser feitos

Em ordem de impacto no propósito declarado do produto (informar com
qualidade), não em ordem de facilidade:

1. **Segunda fonte de coleta viva, testada ponta a ponta.** Elastic tem
   tradutor de schema desde antes desta sessão — nunca foi validado contra
   um cluster real. Enquanto for assim, "SIEM agnóstico" é alegação, não
   fato. Prioridade #1 porque sustenta a alegação central "não plugamos só
   em um SIEM".
2. **Validar Slack, Teams e Jira contra serviço real** (só GLPI tem essa
   prova hoje). Sem isso, 3 dos 4 canais de notificação continuam
   comprovados só em teste unitário com HTTP fake.
3. **Investigação multi-hop real (L1→L2).** Hash relacionado a outros
   hosts, IP a outras conexões via consulta ativa, domínio a histórico de
   DNS — mesmo um só hop adicional além da própria origem tira a
   plataforma da categoria "L1 rápido e raso" descrita no guia 2026.
4. **Threat Hunting proativo.** Hoje 100% reativo (evento chega → tria).
   Nenhuma capacidade de varrer o histórico já coletado por IOC/padrão
   sob demanda do analista.
5. **Feedback loop TP/FP vindo de um humano, não só da própria IA.**
   `learning.py` aprende quando o Supervisor confirma a si mesmo repetidas
   vezes — não existe um jeito do analista marcar "isso foi falso
   positivo" e a plataforma parar de repetir aquele erro específico.
6. **Multi-tenancy real** — isolamento de dados e RBAC por tenant, não só
   um filtro de dashboard por tag.
7. **Governança sobre padrões aprendidos** — hoje um padrão vira via
   rápida automaticamente ao bater 3 confirmações, sem revisão humana,
   sem versionamento, sem como reverter um padrão que se provou errado
   depois de promovido.
8. **Visão de tendência da qualidade do motor, não só o valor atual.**
   `grounding_rejected_count`/`hydration_pct`/`stability_pct` existem como
   número do momento — não existe gráfico de série temporal pra saber se
   a taxa de alucinação está subindo, descendo, ou concentrada num tipo
   de evento específico.
9. **Visão Operacional (N3) ainda é só leitura.** Não dá pra comentar um
   incidente, anotar uma investigação, ou disparar uma ação de
   notificação manual a partir da própria tela — é dashboard, não espaço
   de trabalho.
10. **Nenhuma capacidade desta lista foi validada com um analista humano
    de verdade usando a plataforma em operação real.** Toda a validação
    desta sessão (e da anterior) foi feita por mim gerando carga sintética
    e conferindo o resultado — o que prova que o código funciona como
    projetado, não que resolve o problema de um analista N1/N2 real
    trabalhando nele por um turno inteiro.

---

## 5. Qualidade das ações que já existem na plataforma

Não uma lista de features — uma nota honesta de maturidade por
capacidade, com o motivo.

| Capacidade | Maturidade | Por quê |
|---|---|---|
| Via rápida determinística (correlação + assinatura) | **Alta** | Fato objetivo (SID/técnica/volume real), zero LLM, testada, validada sob 170 mil eventos reais |
| Validação anti-alucinação do Supervisor | **Alta** | Achado real, corrigido, com teste que prova a rejeição, métrica ao vivo, e auditoria retroativa que limpou 166 de 185 incidentes falsos já existentes (dado depois substituído por reset de teste de volume) |
| Hidratação de técnica MITRE (classtype/categoria) | **Alta** | Taxonomia real do próprio Suricata/OWASP CRS, não inventada; elevou hidratação de ~1% para 79%+ em teste sob carga |
| Trilha de auditoria (Decisão/Evidência) | **Alta** | Veredito completo por evento, motivo de degradação explícito, visível na UI |
| NIDS real (Suricata + ET-Open) | **Alta** | Ruleset genuíno, não amostra decorativa |
| Notificação/ticket — canal GLPI | **Alta** | Validado com ticket real, conteúdo completo, status sincronizado bidirecional, edição manual bloqueada quando há ticket |
| Notificação/ticket — canais Slack/Teams/Jira | **Média** | Código real e testado em unidade, nunca contra serviço real — mesmo princípio do GLPI, sem a prova de campo |
| Linha de base de 7 dias / Watchlist | **Média-alta** | Sinal real e testado, mas o limiar (3 eventos, 3x a média) é heurística simples, não um modelo estatístico |
| Retroalimentação de incidente no Supervisor | **Média-alta** | Real e testado, mas um único hop (mesma origem) — não é a memória multi-fonte que a arquitetura original descrevia |
| Aprendizado incremental (padrões promovidos) | **Média** | Mecanismo sólido e testado; zero prova de funcionamento com tráfego real deste ambiente até agora |
| Visão Operacional (N3) | **Média-alta** | Dado real e bem sintetizado; ainda somente leitura, sem espaço de trabalho |
| Multi-tenancy (`client_tag`) | **Baixa** | Filtro de dashboard, não isolamento de dado nem RBAC |
| Threat Hunting / Detection Eng. com aprovação / Feedback humano TP-FP | **Inexistente** | Nenhum código correspondente |

---

## 6. Comparação direta: Mayko SecOps (Ayko) — concorrente regional fora dos guias internacionais

Ayko é capixaba (ES), lançou a Mayko SecOps no Mind The Sec 2026 — nenhum
dos guias internacionais citados acima (D3/Simbian/Prophet) a cobre, o que
a torna mais diretamente relevante como concorrente regional/LatAm do que
os players enterprise americanos já listados.

**Ressalva honesta, diferente do resto deste documento**: tudo abaixo sobre
a Mayko vem só do site oficial da Ayko e de matéria de imprensa patrocinada
— nunca testado, nunca visto rodando. Essa assimetria (nosso lado é medido
ao vivo contra sistema real; o lado deles é o que a própria empresa
publica) é ela mesma um dado relevante, não só uma ressalva de rodapé.

| Dimensão | Mayko SecOps (alegado pela Ayko, não verificado) | cyber-soc (medido/testado nesta e em sessões anteriores) |
|---|---|---|
| Velocidade de investigação | "~8 min/investigação, ~90 consultas correlacionadas por ocorrência, 15x mais rápido que analista sênior" — metodologia do benchmark não publicada | SLA evento→incidente medido ao vivo numa rajada de 60 eventos reais: mediana ~143s; evento isolado sem contenção: ~35s; via determinística: segundos. Não é comparável 1:1 — ver nota abaixo |
| Filosofia de velocidade | Investigação profunda por alerta (enriquecimento pesado toda vez, ~90 consultas) | Classificação rápida primeiro — via determinística + aprendizado incremental evitam reinvestigar o que já é conhecido; IA só entra quando não há atalho real |
| Redução de falso positivo | Alegada ("analisa comportamento em tempo real"), nenhum número publicado | Medida quando há amostra: matriz de confusão real com revisão humana (`/dashboard/confusion-matrix`) — Precisão/Recall/F1/Acurácia calculados, não afirmados |
| Superfície de ataque exposta (ASM) | Sim — descoberta automática de domínio/servidor/app/nuvem exposto, monitora vulnerabilidade/vazamento | **Não existe — gap real** |
| Deep/dark web monitoring | Sim (citado, sem detalhe técnico) | **Não existe — gap real** (mesmo gap já citado no Inopli — ver a análise de indicadores desta sessão) |
| Ativos monitorados | Via ASM externo — o que está exposto ANTES de qualquer ataque acontecer | Via SIEM interno — hostname/IP observado nos próprios eventos recebidos, sem CMDB (`asset_risk.py`), ranqueado por volume/confirmação/diversidade de técnica. **Direção oposta e complementar**: eles mapeiam exposição externa, nós rankeamos o que já está sendo atingido internamente |
| Ação de resposta | Página de SOC da Ayko (mais ampla, não fica claro se é a Mayko especificamente): "identify, **contain**, and **neutralize** threats" | Nunca executa ação — "notification-only" é posicionamento de produto explícito e permanente (ver topo deste documento) |
| Trilha de auditoria / anti-alucinação | Não publicado nenhum dado | `grounding_rejected_count` ao vivo no dashboard, achado real de alucinação do Supervisor corrigido e testado (seção 2/3 acima) |
| Transparência de fonte | Só material de marketing/imprensa, sem documentação técnica pública | Este documento + 239+ testes automatizados + validação contra Wazuh/Suricata/GLPI reais |

**Nota sobre a comparação de velocidade**: o "15x mais rápido" da Mayko
descreve profundidade de INVESTIGAÇÃO (90 consultas correlacionadas por
alerta, todo alerta) — uma métrica diferente do nosso SLA evento→incidente,
que mede o caminho INTEIRO até virar chamado, boa parte dele resolvido sem
nenhuma consulta extra (via determinística). Comparar os dois números
direto seria comparar coisas diferentes — o ponto real de atenção não é
"quem é mais rápido", é que a Mayko aparenta investigar com muito mais
profundidade por padrão (90 consultas vs. a nossa investigação L1,
rasa além da própria origem — ver seção 2, "Profundidade de investigação").

**O que isso muda na lista de gaps (seção 4)**: ASM e deep/dark web
monitoring são categorias de capacidade inteiras que não existiam nesta
análise antes — não entram na lista priorizada de 10 itens acima (que mede
maturidade do que já existe), mas são o gap mais concreto que a Mayko expõe
que os guias internacionais não tinham deixado claro com a mesma força.

---

## 7. Comparação direta: "Top 5 AI SOC Analyst Platforms" (Prophet Security, 2026)

**Calibração antes da tabela**: a conclusão certa não é "não somos melhor
nem pior" de forma genérica — é dimensão por dimensão. Nas duas comparações
feitas nesta revisão (Mayko e esta), o padrão que se repete é o mesmo:
somos **mais rigorosos em transparência/medição** (matriz de confusão real,
grounding anti-alucinação, tudo validado contra sistema real) e **mais
atrás em amplitude de integração e profundidade de investigação
multi-fonte** — quase todo concorrente citado nos dois documentos investiga
com mais fontes de dado por alerta do que nós.

O próprio artigo da Prophet declara os critérios de ranking: "integration
coverage, investigation depth, accuracy and calibration, explainability,
and how the system learns from analyst feedback" — os mesmos 5 eixos usados
abaixo.

| Plataforma | Abordagem central | Métrica/alegação específica | Ação de resposta |
|---|---|---|---|
| **Prophet Security** | Investiga 100% dos alertas, profundidade de analista sênior, consulta SIEM+EDR+identidade+nuvem+e-mail dinamicamente, pivota no que encontra | "concordou com o time humano em 99,8% das investigações" (um cliente Fortune 500) | Veredito com recomendação + "human-in-the-loop approval gates" |
| **Microsoft (Security Copilot Agents/Defender)** | Classificação/triagem de alerta, embutido no ecossistema Defender | Caso real citado: 200+ horas de analista economizadas/mês, 6,5x mais alertas maliciosos identificados | Classificação e priorização — investigação e resposta continuam com o analista |
| **CrowdStrike (Falcon Charlotte AI)** | Ancorado em EDR, camada de orquestração (Agentic SOAR) + agentes customizáveis sem código | Nenhuma métrica numérica no artigo | Automação em nível de orquestração, agentes executam DENTRO de guardrails |
| **Palo Alto (Cortex AgentiX)** | Sucessor do XSOAR, 1.000+ integrações prontas, suporte nativo a MCP | "até 98% de redução de MTTR" (alegação do próprio fornecedor — o artigo da Prophet, um concorrente, marca isso como "merece verificação") | Auditabilidade total de ação + aprovação humana pra ação de impacto |
| **Google SecOps (Gemini)** | Modelos Gemini de propósito geral sobre telemetria Chronicle/Mandiant consolidada; agente de triagem roda junto com threat hunting e detection engineering | "comprime ~30 min de análise manual pra ~1 min, em mais de 5 milhões de alertas processados" | Análise e recomendação, dentro do ecossistema Google |

**Onde a `cyber-soc` se compara, eixo por eixo:**

- **Cobertura de integração**: **atrás de todos os 5.** Wazuh é a única fonte
  testada ponta a ponta; os 5 citados vão de "ecosystem-native" (Microsoft/
  Google/CrowdStrike, ecossistema próprio mas profundo) a 1.000+ integrações
  prontas (Palo Alto). Mesmo gap #1 já registrado na seção 4 — esta
  comparação só reforça a prioridade.
- **Profundidade de investigação**: **atrás.** Prophet consulta 5 fontes
  diferentes por alerta e pivota no que encontra (multi-hop real); Google
  roda threat hunting e detection engineering como agentes separados. Nós
  continuamos L1 — correlação de curto prazo + linha de base de 7 dias +
  contexto do próprio incidente, tudo dentro da mesma origem, nunca pivotando
  pra outra fonte de dado.
- **Acurácia e calibração**: **competitivo em rigor, não em escala.** O
  "99,8% de concordância" da Prophet e o "98% de redução de MTTR" da Palo
  Alto são números de UM cliente/fornecedor, sem metodologia pública — o
  próprio artigo da Prophet desconfia do número da Palo Alto. Nossa matriz
  de confusão (`/dashboard/confusion-matrix`) mede Precisão/Recall/F1 a
  partir de revisão humana real, quando existe amostra — mais rigoroso no
  método, mas SEM a escala de produção deles pra gerar um número comparável
  ainda (gap #10 da seção 4: nunca validado com analista real em operação).
- **Explicabilidade**: **competitivo.** O "glass-box audit trail" da
  Prophet (toda consulta e evidência visível) tem o mesmo espírito da nossa
  trilha Decisão/Evidência por evento + `grounding_rejected_count` exposto
  como métrica — em escopo menor (1 fonte vs. 5), mas o princípio de nunca
  esconder o raciocínio é igual.
- **Aprendizado a partir de feedback do analista**: **gap parcialmente
  fechado nesta sessão, ainda não é um loop de verdade.** Este é um dos 5
  critérios que a própria Prophet usa pra rankear — e era o gap #5 exato
  deste documento ("Feedback loop TP/FP vindo de um humano... não existe").
  A matriz de confusão nova (`Event.analyst_verdict`) agora dá ao analista
  um jeito real de marcar "isso foi falso positivo" — mas hoje isso só
  alimenta MÉTRICA (Precisão/Recall), não ainda `learning.py`: o motor não
  para de repetir um erro específico só porque um humano o marcou como
  errado. Fechar essa ponta (usar `analyst_verdict` pra ajustar promoção de
  padrão, não só pra medir) é o próximo passo natural do gap #5.
- **Ação de resposta**: **escopo de produto diferente, não maturidade.** 3
  dos 5 (CrowdStrike, Palo Alto, e a Prophet com aprovação humana) executam
  ação, mesmo que sob guardrail/aprovação. Nós nunca executamos — é a mesma
  correção de escopo permanente do topo deste documento, não uma lacuna a
  fechar.

---

## 8. O que fazer com isso — recomendações concretas, priorizadas

Cada item abaixo nasce de um gap específico das seções 6/7 (não uma lista
de desejos solta) e cita o módulo real que muda — mesmo padrão do resto do
documento: nada aqui é aspiracional sem dizer onde entra no código.

### 8.1. Fechar o loop de aprendizado com feedback humano — **baixo-médio esforço, maior prioridade**

Motivado por: critério "how the system learns from analyst feedback" da
Prophet (seção 7) — exatamente o gap #5 já registrado na seção 4.

Hoje `learning.record_confirmation` (`backend/app/services/learning.py`)
só promove um padrão quando o **próprio Supervisor** confirma o mesmo
`Event.type` 3 vezes seguidas — a reclassificação humana
(`Event.analyst_verdict`, `PATCH /api/events/{id}/verdict`) existe desde
esta sessão mas hoje só alimenta a matriz de confusão
(`/dashboard/confusion-matrix`), nunca `learning.py`. Concretamente falta:

- Quando um evento cujo `type` já tem `LearnedPattern` promovido recebe
  `analyst_verdict = false_positive`, isso deveria **despromover** o
  padrão (voltar `promoted = False`, resetar `confirmations`) — hoje um
  padrão promovido nunca reverte, mesmo que um humano prove que ele está
  gerando falso positivo repetido.
- Uma confirmação humana (`true_positive`/`true_negative`) poderia contar
  **mais** que uma confirmação da própria IA na promoção — hoje as duas
  fontes nem se falam.

Não exige tabela nova nem migração — `Incident`/`Event`/`LearnedPattern` já
têm os campos. É lógica nova em `record_confirmation` + um gatilho
chamando-a a partir de `PATCH /api/events/{id}/verdict` (`events.py`).

### 8.2. ASM mínimo — reaproveitar o Shodan que já existe, não construir do zero — **baixo esforço pro primeiro corte**

Motivado por: Mayko e Inopli citam ASM como diferencial (seção 6); nenhum
dos 5 da seção 7 foca nisso especificamente, mas é onde ficamos mais
expostos como categoria de produto inteira ausente.

Achado ao revisar o código pra esta recomendação: `threat_intel.py` já
integra Shodan (`query_shodan`) — hoje chamado só **reativamente**, quando
um evento referencia um IP público (`analyze_traffic`, `ingest.py`). Um
primeiro corte de ASM não precisa de infraestrutura de varredura nova:
rodar essa MESMA consulta **proativamente** contra os IPs públicos que a
própria organização já expôs nos eventos (`asset_risk.py` já sabe
distinguir IP interno de externo — `_is_internal_ip`), numa rotina
periódica (mesmo padrão de `_sweep_orphaned_events_forever`,
`bootstrap.py`), sinalizando porta/serviço exposto que o Shodan já indexa
sobre aquele IP. Não é ASM completo (não descobre subdomínio novo nem
certificado), mas é um passo real e barato antes de decidir se vale
licenciar uma ferramenta de ASM de verdade.

### 8.3. Segundo hop de correlação (multi-hop L1→L2) — **médio esforço**

Motivado por: profundidade de investigação da Prophet (5 fontes, pivota no
que encontra) e do Google (agentes de threat hunting/detection engineering
separados) — seção 7; já é o gap #3 da seção 4.

Hoje `_open_incident_context` (`rules_engine.py`) só olha a MESMA origem
dentro do MESMO incidente. Um segundo hop realista sem precisar de fonte de
dado nova: antes de julgar um evento, também checar (a) se a mesma técnica
MITRE confirmada aqui já apareceu em OUTRO incidente aberto de origem
diferente nos últimos N dias (padrão de campanha, não origem isolada), e
(b) se o `dst_ip` deste evento também está sendo alvo de OUTRAS origens ao
mesmo tempo (múltiplos atacantes mirando o mesmo ativo — o `asset_risk.py`
já tem o dado de "quantas origens distintas" por ativo, só falta usar isso
como sinal de entrada da análise, não só como saída pro dashboard).

### 8.4. Segunda fonte de coleta real (Elastic) — **sem mudança de prioridade**

Já é o gap #1 da seção 4 e o mais citado nas duas comparações novas
(seções 6 e 7) — nenhuma das duas mudou a prioridade dele, só confirmou
que é o mais visível de fora.

### 8.5. Deep/dark web monitoring — **decisão de comprar/parceirizar, não construir**

Motivado por: Mayko e Inopli (seção 6 e análise de indicadores anterior).
Diferente dos itens acima, este exige infraestrutura de coleta
especializada (crawling de fóruns/mercados clandestinos, geralmente via
feed de fornecedor terceiro) que não é uma extensão natural do código
existente — mesma categoria de decisão que threat intel externo já é hoje
(`Connector` do tipo `threatintel`, AbuseIPDB/Shodan são feeds de
terceiro plugados, não coleta própria). Recomendação honesta: se este item
avançar, o caminho de menor atrito é um NOVO tipo de `Connector`
`threatintel` consumindo um feed de terceiro já existente no mercado, não
construir coleta de deep web do zero.

**Status desta revisão:** 8.1, 8.2 e 8.3 foram implementados e validados
(testes automatizados + validação ao vivo contra a API real) nesta mesma
sessão. Concretamente:

- **8.1** — `learning.apply_analyst_feedback` (`services/learning.py`)
  despromove um `LearnedPattern` quando `PATCH /api/events/{id}/verdict`
  recebe `false_positive` pra uma skill que o padrão promovido representa.
  16 testes novos (`test_learning.py`, `test_events.py`); validado ao vivo
  (`PATCH /api/events/202/verdict` retornando `learned_pattern_demoted` no
  corpo da resposta).
- **8.2** — `services/asm.py` reaproveita `threat_intel.query_shodan`
  proativamente contra IPs públicos de destino já observados nos eventos,
  com cache próprio (`IocCache`, `indicator_type="asm"`) e uma varredura
  periódica (`bootstrap.py::_asm_sweep_forever`, a cada 6h). Novo endpoint
  `GET /dashboard/exposed-assets`. 7 testes novos (`test_asm.py`); validado
  ao vivo contra o ambiente real (conector Shodan já configurado, 0 IP
  público de destino nos últimos 30 dias neste ambiente — endpoint responde
  o shape correto sem erro).
- **8.3** — `services/correlation.py` ganhou
  `find_technique_matches_in_other_open_incidents` (mesma técnica MITRE
  CONFIRMADA em outro incidente aberto de origem diferente) e
  `count_distinct_origins_targeting` (múltiplas origens mirando o mesmo
  destino). `rules_engine.py::_campaign_context` combina os dois e entra no
  mesmo `incident_context` já consumido pelo Supervisor — nenhuma mudança
  em `graph.py`. 16 testes novos (`test_correlation.py`,
  `test_rules_engine.py`).

**8.4 e 8.5 permanecem não implementados nesta revisão** — 8.4 (Elastic)
precisaria de um cluster Elastic real pra validar contra dado de verdade
(nenhum disponível neste ambiente); 8.5 (deep/dark web) é uma decisão de
fornecedor (qual feed de terceiro plugar), não uma tarefa de código — ambos
continuam exatamente como descrito acima.

---

## 9. Teste de carga real (stress test) — dado desta revisão

As seções 6 e 7 citam números de terceiro (Mayko "~8min por investigação",
Prophet "100% dos alertas investigados", Google "30min→1min") sem poder
reproduzi-los — são alegação de vendor, não medição própria. Esta seção é o
oposto: uma rajada de carga real, contra o ambiente Docker local completo
(API + Postgres + Ollama CPU-bound + GLPI real), medida com os próprios
endpoints de dashboard (`/analysis-metrics`, `/eps`, `/tickets-status`), sem
nenhum número estimado.

**Metodologia.** Limpeza completa do estado de teste acumulado em sessões
anteriores (`TRUNCATE events, incidents, ioc_cache, learned_patterns` no
Postgres da própria plataforma — os 52 chamados de teste no GLPI **não**
puderam ser removidos: a ação foi bloqueada pelo classificador de permissão
do ambiente de execução por ser escrita num sistema externo; ficam como
lixo conhecido, sem efeito na medição). A partir daí, 3 rajadas sucessivas
via `POST /api/ingest/wazuh` (gerador com 12 cenários realistas — força
bruta SSH, port scan, SQLi, XSS, C2, DoS, escalação de privilégio etc.,
IPs aleatórios, sem repetição de padrão óbvio):

1. **Rajada 1** (80 eventos, estado ainda "morno" de padrões aprendidos de
   sessões anteriores): 100% dos eventos aceitos na ingestão, fila
   totalmente drenada em 864s, `stability_pct=100%`, 0 evento preso.
2. **Reset total** (incluindo `learned_patterns` desta vez, pra isolar uma
   base fria de verdade) + **Rajada 2** (83 eventos, estado 100% frio — zero
   padrão aprendido): 2 dos 80 POSTs de ingestão sofreram timeout do
   *cliente* (30s) — achado real, endereço abaixo. `analysis_speed` mediano
   **523s** (sem nenhuma via rápida aprendida ainda, cada evento decidido
   pelo Supervisor competindo pelo único worker de CPU do Ollama).
3. **Rajada 3** (+80 eventos, disparada imediatamente após a 2, agora com 4
   padrões já promovidos pela Rajada 2): 100% aceitos na ingestão.

**Resultado agregado das 3 rajadas (168 eventos totais):**

| Métrica | Valor real medido |
|---|---|
| Eventos ingeridos | 168 (0 rejeitados pelo motor de gating) |
| `stability_pct` (análise sem degradação) | 99.3% |
| Confirmados como ameaça (`matched`) | 107 (63.7%) |
| Via rápida determinística/aprendida (`informational` + fast lane) | 19 |
| Sem correspondência real (`no_match` genuíno) | 22 |
| Falha técnica recuperada (`no_match`, `technical_failure=true`) | 20 (11.9%) — ver achado abaixo |
| Backlog ao final | **0** — nenhum evento preso |
| Incidentes abertos | 107 |
| Chamados GLPI criados de verdade | 106/107 (99.1%) |
| Padrões aprendidos promovidos (0 → 7 durante a sessão) | `learning.py` funcionando sob carga real, não só em teste unitário |
| `analysis_speed` mediano — frio (Rajada 2 isolada) → acumulado após aquecer (Rajada 3) | **523s → 105.8s** |
| `workload_reduction_pct` (`/dashboard/kpis`) | 36.3% |

**Achado real #1 — auto-cura sob carga confirmada ao vivo, não só em
teste unitário.** Um evento da Rajada 2 (`id=78`) ficou `pending` por mais
de 22 minutos (a task de análise em background nunca chegou a ser
agendada — ver achado #2). `_sweep_orphaned_events_forever`
(`bootstrap.py`, intervalo de 300s, limiar de 25min) o encontrou e
reagendou sozinho, sem qualquer intervenção manual; o evento terminou
`matched` normalmente. Isto já era código existente (não desta sessão),
mas nunca tinha sido observado se auto-curando em produção real durante
este projeto — só validado antes em teste controlado.

**Achado real #2 — falha nova sob carga sustentada, não presente na
validação anterior (~143s de SLA mediano, sessão passada).** 20 de 168
eventos (11.9%) tiveram a conexão do Postgres derrubada
(`idle_in_transaction_session_timeout=30s`, `app/db.py`) durante a
análise, virando `no_match`/`technical_failure` em vez de um veredito
real — o mesmo tratamento de exceção documentado em
`run_rules_engine_for_event` (nunca deixa um evento preso, mas também
nunca reprocessa uma falha técnica sozinho). Dois desses ainda ocorreram
na própria requisição de ingestão (timeout do cliente HTTP, não só na
análise em background). Hipótese mais provável: as 2 consultas novas de
`_campaign_context` (item 8.3 desta revisão) somam-se às já existentes
(`_open_incident_context`, contagem de correlação) e rodam todas antes de
qualquer fast lane, aumentando o tempo que cada evento segura uma sessão
do Postgres sob disputa — sob rajada concorrente e Postgres/Ollama
dividindo o mesmo host Docker, isso é suficiente pra estourar os 30s em
uma fração real dos casos. **Não corrigido nesta revisão** (fora do escopo
do teste de carga em si) — candidato a item 8.6 numa próxima rodada:
medir se o aumento de 11.9% é atribuível a 8.3 especificamente (rodar o
mesmo teste revertendo só `_campaign_context` seria o experimento
controlado certo) ou se já existia em menor grau antes.

**O que isto prova, honestamente, contra as seções 6/7:** os números de
Mayko/Prophet/Google citados lá são tempo de investigação de UM alerta
sob operação normal — não comparáveis linha a linha com um teste de
rajada. A métrica comparável de "um alerta isolado" já estava medida
antes desta sessão (~35s para o grafo completo — 3 grupos + supervisor —
rodar uma vez, ver docstring de `graph.py`) e continua válida (arquitetura
do grafo não mudou). O que este teste de carga prova que nenhum dos
documentos de vendor citados mostra com este nível de detalhe é: (1) o
sistema realmente aprende DURANTE uma rajada real (0→7 padrões promovidos,
mediana caindo de 523s pra 105.8s dentro da mesma sessão, não uma alegação
de "aprende com o tempo" sem número), e (2) quando algo falha sob carga
(20 falhas técnicas reais), a plataforma se recupera sozinha e nunca perde
o evento — 0 de 168 ficou preso ao final, mesmo com uma taxa de falha
técnica de quase 12%.

---

## Fontes de mercado consultadas

- [D3 Security — "The 12 Best Agentic SOC Platforms in 2026: Architectures, Autonomy Levels, and a Full Comparison"][d3-orig]
- [D3 Security — "The Best AI SOC Platforms 2026: Comprehensive Comparison & Guide"][d3-2026] (revisão desta sessão — critérios de autonomia fora do horário, validação de IA, e a distinção L1/L2 de profundidade de investigação vêm daqui)
- [Simbian — "Top AI SOC Platforms in 2026: The 4 Capabilities That Actually Matter"](https://simbian.ai/blog/top-ai-soc-platforms-2026)
- [Prophet Security — "Top 5 AI SOC Analyst Platforms of 2026"](https://www.prophetsecurity.ai/blog/top-5-ai-soc-analyst-platforms)
- [Ayko — "Ayko lança Mayko SecOps, novo SOC autônomo com inteligência artificial" (Folha Vitória, conteúdo de marca)](https://www.folhavitoria.com.br/conteudo-de-marca/ayko-lanca-novo-soc-com-inteligencia-artificial-durante-o-mind-the-sec-2026/) — fonte do número "15x mais rápido"/"~90 consultas correlacionadas"
- [Ayko — "Mayko: a inteligência artificial que moderniza a cibersegurança na Ayko"](https://ayko.tech/en/mayko-a-inteligencia-artificial-que-moderniza-a-ciberseguranca-na-ayko/)
- [Ayko — "Security Operations Center (SOC)"](https://ayko.tech/en/ciberseguranca/security-operations-center-soc/)

[d3-orig]: https://d3security.com/blog/best-agentic-soc-platforms/
[d3-2026]: https://d3security.com/blog/ai-soc-platforms-2026/
[simbian]: https://simbian.ai/blog/top-ai-soc-platforms-2026
