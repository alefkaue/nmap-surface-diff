# Nmap Surface Diff

[![Tests](https://github.com/alefkaue/nmap-surface-diff/actions/workflows/tests.yml/badge.svg)](https://github.com/alefkaue/nmap-surface-diff/actions/workflows/tests.yml)

Inventário e comparação **offline** de relatórios XML do Nmap. Ajuda a revisar mudanças na superfície observada: novos endpoints, endpoints não observados e mudanças no rótulo de serviço. Não executa o Nmap nem envia tráfego.

## Executar

Python 3.11+; somente biblioteca padrão. Nmap não é necessário para os exemplos sintéticos.

```console
git clone https://github.com/alefkaue/nmap-surface-diff.git
cd nmap-surface-diff
python nmap_surface_diff.py examples/after.xml --before examples/before.xml
python -m unittest discover -s tests -v
```

Resultado esperado: portas TCP **443 e 3389** em `newly_observed`; **80** em `not_observed`. As portas 22 e 3389 do relatório atual recebem itens de revisão contextual. O código de saída é **1**, indicando itens para revisar ou diferenças.

Sem `--before`, produz somente inventário e revisão. Saída JSON; código **0** sem itens de revisão/diferenças, **1** com itens ou diferenças, **2** erro. Uma execução idêntica ainda pode retornar 1 se houver portas selecionadas para revisão.

## Interpretação

| Campo | Significado |
| --- | --- |
| `inventory.endpoints` | Endereço, protocolo, porta, rótulo e método de identificação do serviço |
| `review` | Portas selecionadas por um catálogo pequeno e explícito no código |
| `changes.newly_observed` | Endpoint presente apenas no relatório atual |
| `changes.not_observed` | Endpoint antes aberto, ausente dos abertos atuais; não comprova fechamento |
| `changes.service_changed` | Mudança no rótulo ou método de identificação |
| `scope_changed` / `host_set_changed` | Diferenças nas declarações de portas/protocolos e nos hosts up |

O método `table` representa identificação por tabela de portas, não confirmação por probe. Rótulos não comprovam produto, versão, vulnerabilidade ou exposição à Internet. Compare relatórios produzidos com escopo, ponto de observação e opções equivalentes.

## Arquitetura e limites

`XML UTF-8 → validação básica → endpoints exatamente open → inventário → diferença por IP/protocolo/porta`. Aceita TCP, UDP e SCTP no inventário. Hosts sem estado `up` e estados como `open|filtered` não entram no inventário de abertos. Usa o primeiro endereço IPv4/IPv6 de cada host; não correlaciona hosts por MAC ou hostname.

Exige marcador de finalização `exit="success"`; relatórios parciais causam erro. A CLI limita cada entrada a 8 MiB. Permite o DOCTYPE simples do Nmap, mas rejeita DTDs externos e declarações de entidades. Não executa scripts NSE contidos no relatório e não interpreta seus resultados. O XML permanece em memória.

A comparação de escopo considera somente `scaninfo` (protocolo e lista de serviços), não todas as opções do Nmap, filtros de rede ou mudanças de rota. A ausência de `scaninfo` não impede a análise, mas reduz a informação disponível. Diferenças de hosts também não comprovam remoção de ativos.

## Demonstração para entrevista

Compare os exemplos e explique por que uma porta pode deixar de ser observada sem ter sido fechada. Altere o protocolo ou a lista de portas em `scaninfo` e observe `scope_changed`. Próxima evolução: comparar proveniência e opções de coleta de forma estruturada.

Referência: [documentação oficial do XML do Nmap](https://nmap.org/book/output-formats-xml-output.html).

Projeto educacional independente, desenvolvido com assistência de IA. Exemplos sintéticos; licença MIT.
