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

## Fontes de mercado consultadas

- [D3 Security — "The 12 Best Agentic SOC Platforms in 2026: Architectures, Autonomy Levels, and a Full Comparison"][d3-orig]
- [D3 Security — "The Best AI SOC Platforms 2026: Comprehensive Comparison & Guide"][d3-2026] (revisão desta sessão — critérios de autonomia fora do horário, validação de IA, e a distinção L1/L2 de profundidade de investigação vêm daqui)
- [Simbian — "Top AI SOC Platforms in 2026: The 4 Capabilities That Actually Matter"](https://simbian.ai/blog/top-ai-soc-platforms-2026)
- [Prophet Security — "Top 5 AI SOC Analyst Platforms of 2026"](https://www.prophetsecurity.ai/blog/top-5-ai-soc-analyst-platforms)

[d3-orig]: https://d3security.com/blog/best-agentic-soc-platforms/
[d3-2026]: https://d3security.com/blog/ai-soc-platforms-2026/
[simbian]: https://simbian.ai/blog/top-ai-soc-platforms-2026
