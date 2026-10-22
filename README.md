# PHP Security Response

Skill para triagem defensiva e autorizada de servidores PHP: identificar runtimes potencialmente vulneráveis, comparar caminhos de correção, investigar sinais de comprometimento e documentar risco residual.

## Por que esta skill foi criada

Ela foi criada após a divulgação, em 21 de outubro de 2026, de duas vulnerabilidades críticas no PHP — CVE-2026-109618 e CVE-2026-109619 — que podem permitir execução remota de código em instalações que atendem requisições web. O incidente mostrou que descobrir a versão correta, confirmar backports de fornecedores, atualizar todos os processos e investigar o período de exposição exige cuidado.

A skill padroniza esse trabalho para reduzir comandos improvisados e evitar conclusões baseadas só na versão do PHP CLI. As informações do incidente ficam em `references/php-2026-10-21.md`; elas são datadas e precisam ser conferidas nas fontes oficiais em cada uso.

## Como usar

No ChatGPT/Codex, peça a análise usando o nome **php-security-response** e indique o ambiente, o escopo e o que está autorizado. Exemplos:

> Use a skill php-security-response para fazer uma triagem somente de leitura no servidor de homologação `app-staging`. Tenho autorização para consultar o runtime, os containers e os logs do período de 21/10/2026 até hoje. Não faça alterações.

> Use a skill php-security-response para avaliar os serviços PHP deste Compose. Primeiro faça o inventário e investigue indícios no período de exposição. Apresente opções de correção com impacto, teste e rollback; aguarde minha aprovação explícita antes de atualizar ou reiniciar qualquer serviço.

A skill conduz o trabalho nesta ordem:

1. Confirma autorização, escopo, limites e se há uma janela de manutenção.
2. Identifica o runtime que realmente atende tráfego e separa CLI, FPM, containers, workers e cron.
3. Confere advisories oficiais e evidências de backport do fornecedor.
4. Investiga sinais disponíveis no período de exposição sem executar payloads ou limpar evidências.
5. Compara correções pelo risco, compatibilidade, indisponibilidade, cobertura, teste e rollback.
6. Pede aprovação explícita para cada mudança de sistema e valida o resultado depois da execução.
7. Entrega o relatório de `references/modelo-relatorio.md`, incluindo limites e risco residual.

Não forneça acesso a sistemas de terceiros sem autorização. Uma aprovação para consultar não autoriza atualização, reinício, bloqueio, rotação de credenciais, remoção de arquivos ou outra alteração.

## Scripts incluídos

Os scripts abaixo são auxiliares de **somente leitura**. Eles não corrigem, reiniciam, removem nem alteram serviços. Execute-os apenas em alvos autorizados e dentro do escopo aprovado. Os caminhos e metadados podem ser sensíveis; revise e sanitize a saída antes de compartilhá-la.

| Script | Para que serve | Exemplo |
|---|---|---|
| `scripts/php_host_inventory.sh` | Lista executáveis PHP encontrados em caminhos comuns, versões de pacotes e unidades PHP-FPM do systemd. | `bash scripts/php_host_inventory.sh` |
| `scripts/php_docker_inventory.sh` | Sem argumentos, lista containers ativos. Com nomes/IDs exatos, mostra nomes dos processos (sem argumentos) e consulta versões PHP, sem imprimir variáveis de ambiente. | `bash scripts/php_docker_inventory.sh`; depois `bash scripts/php_docker_inventory.sh app-web app-worker` |
| `scripts/php_version_gate.py` | Compara uma versão observada com os pisos de correção upstream publicados para as CVEs de outubro de 2026. É uma verificação preliminar, não valida backports. | `python3 scripts/php_version_gate.py 'PHP 8.3.35 (cli)'` |
| `scripts/php_file_triage.py` | Lista arquivos modificados desde uma data em diretórios indicados, com metadados e SHA-256 limitado por tamanho; não exibe o conteúdo dos arquivos. | `python3 scripts/php_file_triage.py --root /var/www/app --since 2026-10-21T14:00:00Z` |
| `scripts/php_log_triage.py` | Conta erros genéricos de memória, erros fatais e timeouts em arquivos de log indicados. Suporta `.gz`, janela opcional e não imprime linhas encontradas. | `python3 scripts/php_log_triage.py --after 2026-10-21T14:00:00Z /var/log/php-fpm.log /var/log/php-fpm.log.1.gz` |

Rode os comandos a partir da pasta da skill ou substitua `scripts/...` pelo caminho absoluto correspondente. `php_host_inventory.sh` é voltado a hosts Linux com Bash; `php_docker_inventory.sh` precisa do Docker CLI e acesso ao daemon/contexto autorizado; os dois scripts Python precisam do Python 3.

### Limites dos scripts

- O inventário do host não prova qual runtime atende requisições. Compare com a configuração e o processo real do servidor web.
- O inventário Docker só consulta containers explicitamente selecionados no contexto Docker ativo; não alcança Kubernetes, outros contextos ou runtimes não selecionados. A listagem de processos pode não estar disponível em todo host Docker.
- O comparador de versão usa versões upstream conhecidas para as CVEs indicadas. Um pacote de distribuição pode conter backport mesmo com número aparentemente antigo; valide com o fornecedor.
- Arquivos recentes podem ser deploys legítimos. Compare caminhos, hashes e horários com artefatos confiáveis e registros de implantação.
- As contagens de log são heurísticas genéricas. Não encontrar essas mensagens não demonstra ausência de exploração. Correlacione logs de aplicação, proxy, servidor web e sistema.
- A triagem de arquivos limita a profundidade a 12 níveis, a varredura a 10.000 diretórios e 50.000 arquivos, os resultados a 2.000 arquivos, o hash a 64 MiB por arquivo e 512 MiB no total. A triagem de logs lê até 256 MiB por arquivo e ignora linhas maiores que 1 MiB. Esses limites podem deixar conteúdo sem examinar; registre truncamentos e hashes indisponíveis no relatório.
- Nenhum script executa teste de exploração. Nenhum resultado confirma ou descarta sozinho uma invasão.

## Segurança e correção

Antes de qualquer alteração, a skill apresenta alvos, comandos, impacto provável, serviços que serão reiniciados, backup, validação, rollback e risco residual. Mudanças só podem ocorrer após aprovação explícita do usuário para os alvos e ações descritos. Se o ambiente divergir do plano aprovado, a execução deve parar.

Os scripts foram deliberadamente limitados a inventário e triagem. A atualização precisa ser escolhida conforme distribuição, imagem, fornecedor, dependências e arquitetura do servidor; não há um comando universal seguro para atualizar qualquer servidor PHP.

## Aviso e apoio profissional

Esta skill ajuda na triagem, mas não é infalível e não certifica que um servidor esteja livre de vulnerabilidades ou invasões. Se não se sentir seguro com a análise ou a correção, pare antes de qualquer mudança e fale com Guilherme Niederauer pelo Instagram **[@guiniederauer](https://instagram.com/guiniederauer)**, com a INOVATI pelo Instagram **[@inovati_oficial](https://instagram.com/inovati_oficial)** ou pelo site [inovati.online](https://inovati.online).

Consulte o arquivo `LICENSE` para os termos de uso e redistribuição.
