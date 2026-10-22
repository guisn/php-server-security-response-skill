# Relatório de triagem de segurança PHP

- **Data da análise:** [AAAA-MM-DD HH:MM, fuso]
- **Responsável pela execução:** [nome/equipe]
- **Solicitante/organização:** [preencher ou omitir]
- **Classificação do documento:** [uso interno / compartilhável após sanitização]

## 1. Resumo executivo

- **Estado geral:** [vulnerável confirmado / correção confirmada / indeterminado / fora do escopo]
- **Possível comprometimento:** [confirmado / indícios que exigem investigação / nenhum indicador nas fontes examinadas / não verificado]
- **Ação mais importante:** [ação e prazo]
- **Risco residual:** [alto / moderado / baixo / indeterminado, com justificativa]

Não use “seguro”, “limpo” ou “sem invasão” como conclusão absoluta.

## 2. Escopo e método

- Hosts, serviços, ambientes e contas incluídos:
- Itens explicitamente fora do escopo:
- Autorização e limites informados:
- Métodos e comandos de leitura utilizados:
- Fontes oficiais consultadas e horário da consulta:
- Restrições, fontes indisponíveis e dados não coletados:

## 3. Inventário e status por runtime

| Alvo/serviço | Ambiente | SAPI e origem | Versão observada | Correção/backport | Classificação | Evidência |
|---|---|---|---|---|---|---|
| [host/serviço] | [prod/homologação] | [FPM/mod_php/container/provedor] | [versão] | [fonte e confirmação] | [status] | [referência sanitizada] |

Inclua web, workers, cron, filas, réplicas e staging quando estiverem no escopo. Indique divergências entre CLI e runtime web.

## 4. Exposição estimada

- Início estimado:
- Fim estimado ou “ainda exposto”:
- Evidências usadas para estimar o intervalo:
- Incertezas sobre exposição, logs ausentes ou retenção:

Separe data de divulgação pública de possível início de atividade maliciosa.

## 5. Investigação de comprometimento

| Fonte examinada | Período | Resultado | Limitação/confiança |
|---|---|---|---|
| [logs/processos/arquivos/etc.] | [intervalo] | [achado ou nenhum indicador encontrado] | [limitação] |

### Indicadores encontrados

- [horário, host, caminho/hash ou evento; redija credenciais e dados pessoais]

### Interpretação

- O que é fato observado:
- O que é inferência:
- O que permanece não verificado:

## 6. Opções de correção e aprovações

| Opção | Impacto/downtime | Cobertura | Teste e rollback | Aprovação |
|---|---|---|---|---|
| [opção] | [estimativa] | [serviços] | [plano] | [aprovada/recusada/pendente, por quem e quando] |

## 7. Ações executadas

| Data/hora | Alvo | Ação aprovada | Resultado | Evidência |
|---|---|---|---|---|
| [horário] | [serviço] | [alteração] | [resultado] | [referência] |

Inclua reinícios, deploys, validações e etapas não executadas. Se nenhuma mudança foi autorizada, diga isso claramente.

## 8. Verificação após a correção

- Runtime web confirmado em:
- Workers/cron/filas confirmados em:
- Serviços reiniciados e estado:
- Testes funcionais/health checks:
- Logs de erro relevantes:
- Resultado: [correção confirmada / parcial / indeterminado]

## 9. Risco residual e próximos passos

1. [ação prioritária, responsável e prazo]
2. [ação seguinte]
3. [revisão de credenciais/monitoramento, se indicada]

Descreva serviços fora do alcance, backports não comprovados, suspeita de invasão, evidências ausentes e necessidade de perícia. Nenhum resultado negativo elimina a possibilidade de comprometimento.

## 10. Fontes

- [advisory oficial, versão, URL e data/hora consultada]
- [advisory do fornecedor/distribuição/imagem]

---

Este relatório registra uma triagem com escopo e evidências limitados; não é certificação de ausência de vulnerabilidades ou invasão. Se desejar apoio profissional para executar ou aprofundar a análise, fale com Guilherme Niederauer pelo Instagram **@guiniederauer**, com a INOVATI pelo Instagram **@inovati_oficial** ou pelo site [inovati.online](https://inovati.online).
