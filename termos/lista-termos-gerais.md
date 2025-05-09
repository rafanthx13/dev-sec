# Termos gerais

## By Chatpgt

Claro, Rafael! Abaixo está uma lista com os **principais termos de AppSec (Segurança de Aplicações)** para aplicações web, com **nomes, siglas, explicações simples e exemplos práticos**:

---

## 🔐 **Principais termos de AppSec para Web**

| Termo / Sigla                     | Nome completo                    | O que é                                                   | Exemplo prático                                          |
| --------------------------------- | -------------------------------- | --------------------------------------------------------- | -------------------------------------------------------- |
| **XSS**                           | Cross-Site Scripting             | Injeção de scripts maliciosos no navegador da vítima      | `<script>alert(1)</script>` em um campo de comentário    |
| **SQLi**                          | SQL Injection                    | Injeção de comandos SQL por entradas do usuário           | `' OR 1=1 --` em um campo de login                       |
| **CSRF**                          | Cross-Site Request Forgery       | Forçar o navegador do usuário a executar ações sem querer | Link que faz o usuário transferir dinheiro sem perceber  |
| **IDOR**                          | Insecure Direct Object Reference | Acesso a dados de outros usuários sem autorização         | Acessar `/perfil/123` mesmo sendo o usuário 122          |
| **RCE**                           | Remote Code Execution            | Execução remota de código arbitrário no servidor          | Upload de um arquivo `.php` com código malicioso         |
| **LFI / RFI**                     | Local/Remote File Inclusion      | Inclusão de arquivos locais ou remotos indevidamente      | `?page=../../etc/passwd` ou `?page=http://malicioso.com` |
| **Open Redirect**                 | Redirecionamento não validado    | Redirecionamento para sites externos sem controle         | `?redirect=http://phishing.com`                          |
| **XXE**                           | XML External Entity Injection    | Ataque que explora processamento inseguro de XML          | Enviar XML que lê arquivos do servidor                   |
| **SSRF**                          | Server-Side Request Forgery      | Forçar o servidor a acessar URLs internas                 | `curl http://localhost:8080/admin` por input externo     |
| **Broken Auth**                   | Autenticação quebrada            | Falhas no login, sessão ou autenticação multifator        | Login sem validação de senha correta                     |
| **Security Misconfig**            | Configuração insegura            | Exposição de portas, debugs, headers ou permissões        | `APP_DEBUG=true` em produção                             |
| **Sensitive Data Exposure**       | Exposição de dados sensíveis     | Vazar informações como CPF, senhas ou tokens              | Mostrar stack trace com dados do usuário                 |
| **Clickjacking**                  | Engano visual com iframes        | Usuário clica em algo escondido numa página               | Iframe invisível sobre botão de logout                   |
| **Brute Force**                   | Tentativa de força bruta         | Testar várias senhas até acertar                          | `admin` + `123456`, `senha1`, `qwerty`, etc.             |
| **Rate Limiting**                 | Limitação de requisições         | Prevenção contra excesso de tentativas / abusos           | API sem limite sendo sobrecarregada                      |
| **DoS / DDoS**                    | (Distributed) Denial of Service  | Tornar o serviço indisponível                             | Enviar milhões de requisições para sobrecarregar         |
| **Logging & Monitoring Failures** | Falhas de rastreamento           | Não registrar nem alertar eventos suspeitos               | Login suspeito sem alerta no sistema                     |
| **Broken Access Control**         | Controle de acesso quebrado      | Usuário acessa recursos sem permissão                     | Usuário comum acessa rota de admin                       |

---

### 📌 Extras úteis:

* **CSP** (Content Security Policy): proteção contra XSS configurando headers.
* **HSTS** (HTTP Strict Transport Security): força uso de HTTPS.
* **JWT** (JSON Web Token): usado para autenticação baseada em tokens.
* **ACL** (Access Control List): define quem pode acessar o quê.
* **IAM** (Identity and Access Management): gestão de identidades e permissões.

---

Se quiser, posso gerar essa lista em `.csv`, `.pdf`, `.md` ou até como cards de estudo para revisão. Gostaria disso?

--=====================
--=====================
--=====================

## Perplexity

<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" class="logo" width="120"/>

# Principais Termos de AppSec no Contexto de Aplicações Web: Glossário Estratégico

A segurança de aplicações web (AppSec) engloba um léxico técnico essencial para compreender e mitigar riscos cibernéticos. Abaixo, exploramos os conceitos fundamentais, seus significados e contextos de aplicação, baseando-nos nas melhores práticas e fontes especializadas.

## Metodologias e Processos de AppSec

**DevSecOps** representa a integração contínua de práticas de segurança no ciclo de vida de desenvolvimento (SDLC), visando detectar vulnerabilidades desde as fases iniciais[^5][^6]. Essa abordagem contrasta com modelos tradicionais, onde a segurança era tratada apenas em etapas finais, aumentando custos e riscos. O **OWASP Top 10**, listagem atualizada periodicamente pela Open Web Application Security Project, cataloga as vulnerabilidades mais críticas em aplicações web, como injeção SQL e quebra de autenticação, servindo como referência global para priorizar mitigações[^1][^5].

A **Gestão de Vulnerabilidades** envolve identificação, classificação e correção sistemática de falhas, utilizando ferramentas como **SAST** (Static Application Security Testing), que analisa código-fonte em repouso, e **DAST** (Dynamic Application Security Testing), que testa aplicações em execução simulando ataques[^5][^6]. Complementarmente, o **IAST** (Interactive Application Security Testing) combina ambas as abordagens, oferecendo detecção em tempo real durante testes funcionais[^5].

## Vulnerabilidades e Ameaças Comuns

A **Injeção SQL** persiste como uma das falhas mais críticas, permitindo que atacantes executem comandos maliciosos em bancos de dados através de entidades não sanitizadas[^1][^6]. O **XSS** (Cross-Site Scripting) habilita a inserção de scripts em páginas web, comprometendo sessões de usuários e roubando dados sensíveis[^6][^7]. Outra ameaça relevante é o **Zero Day**, referente a vulnerabilidades desconhecidas pelos desenvolvedores, exploradas antes que patches estejam disponíveis[^5].

APIs, componentes críticos em arquiteturas modernas, são alvos frequentes de **Broken Object Level Authorization (BOLA)**, onde falhas de autorização permitem acesso não autorizado a recursos[^5][^6]. Já o **CSRF** (Cross-Site Request Forgery) engana usuários autenticados para executar ações indesejadas, como transferências bancárias não autorizadas[^5].

## Ferramentas e Técnicas de Proteção

O **Web Application Firewall (WAF)** atua como barreira defensiva, filtrando solicitações maliciosas com base em assinaturas conhecidas e comportamentos anômalos[^2][^5]. Para aplicações em contêineres, a **Container Security** abrange a análise de imagens em busca de vulnerabilidades e a aplicação de políticas de runtime[^5].

O **RASP** (Runtime Application Self-Protection) monitora o comportamento da aplicação em execução, bloqueando atividades suspeitas como acesso a arquivos sensíveis ou chamadas de sistema não autorizadas[^5]. Em ambientes de nuvem, o **CSPM** (Cloud Security Posture Management) garere a conformidade contínua com políticas de segurança, identificando configurações errôneas em serviços como AWS S3 ou Azure Blob Storage[^5].

## Padrões e Conformidade

O **CVE** (Common Vulnerabilities and Exposures) é um sistema internacional que cataloga vulnerabilidades de software, facilitando a comunicação entre equipes e a priorização de correções[^5]. Normas como **GDPR** e **PCI DSS** exigem a implementação de controles específicos, como criptografia de dados e gestão de acesso, para proteger informações pessoais e financeiras[^4][^5].

A **Análise de Composição de Software (SCA)** identifica componentes de código aberto vulneráveis em dependências de projetos, crucial para evitar brechas como as exploradas no incidente do Log4j em 2021[^5][^6]. Já o **Secure Coding** envolve práticas de desenvolvimento que previnem vulnerabilidades desde a escrita do código, como validação de entradas e uso de APIs seguras[^5][^7].

## Autenticação e Gerenciamento de Acesso

A **Autenticação Multifator (MFA)** adiciona camadas de verificação além de senhas, reduzindo riscos de comprometimento de contas[^7]. O **OAuth 2.0** e **OpenID Connect** são protocolos amplamente adotados para autorização e autenticação em APIs e sistemas distribuídos, assegurando que tokens de acesso não sejam reutilizados ou expostos[^5][^6].

Para credenciais e segredos, o **Gerenciamento de Secretos** automatiza a rotação de chaves API, tokens e senhas, armazenando-os em cofres digitais como HashiCorp Vault ou AWS Secrets Manager[^5]. A **Gestão de Identidade e Acesso (IAM)** define políticas granulares, garantindo que usuários e sistemas tenham apenas os privilégios necessários (princípio do menor privilégio)[^5][^7].

## Monitoramento e Resposta a Incidentes

O **SIEM** (Security Information and Event Management) agrega e correlaciona logs de múltiplas fontes, detectando padrões suspeitos como múltiplas tentativas de login falhas[^5]. Em casos de violação, o **Plano de Resposta a Incidentes** estabelece etapas para contenção, erradicação e recuperação, minimizando danos financeiros e reputacionais[^5][^7].

A **Análise Forense Digital** recupera e preserva evidências de ataques, identificando vetores de invasão e melhorando defesas futuras[^5]. Ferramentas como **OSINT** (Open Source Intelligence) ajudam a identificar exposição acidental de dados em repositórios públicos ou fóruns[^6].

## Tendências Emergentes

A **Segurança de APIs** ganhou destaque com a ascensão de arquiteturas microservices, exigindo validação rigorosa de parâmetros, limitação de taxas (rate limiting) e proteção contra ataques de injeção específicos como GraphQL Bombs[^5][^6]. Já a **Shift-Left Security** integra testes de segurança nas fases iniciais do desenvolvimento, reduzindo custos e retrabalho através de ferramentas como linters e hooks Git pré-commit[^6][^7].

Com a escalada de ataques a cadeias de suprimentos, a **SBOM** (Software Bill of Materials) documenta todos os componentes de terceiros em uma aplicação, facilitando a resposta a vulnerabilidades como as em bibliotecas log4j ou Spring4Shell[^5][^6].

<div style="text-align: center">⁂</div>

[^1]: https://owasp.org/Top10/pt_BR/

[^2]: https://www.huge-networks.com/blog/noticias/owasp-top-10-como-proteger-suas-aplicacoes-web-contra-as-ameacas-da-lista

[^3]: https://forum.nos.pt/seguranca-98/glossario-da-seguranca-online-43287

[^4]: https://nova8.com.br/o-que-e-appsec-e-sua-importancia/

[^5]: https://www.microfocus.com/media/guide/appsec-cheat-sheet-guide.pdf

[^6]: https://dev.to/thenjdevopsguy/appsec-the-security-specialty-that-rules-them-all-47c4

[^7]: https://www.appsecengineer.com/blog/application-security-and-types

[^8]: https://king.host/wiki/artigo/glossario-de-seguranca-web/

[^9]: https://xygeni.io/pt/sscs-glossary/what-is-application-security-appsec/

[^10]: https://www.convisoappsec.com/glossario/appsec

[^11]: https://www.f5.com/pt_br/glossary/owasp

[^12]: https://www.blackduck.com/glossary.html

[^13]: https://www.blackduck.com/glossary.html

[^14]: https://www.f5.com/pt_br/glossary

[^15]: https://owasp.org/API-Security/editions/2019/pt-BR/dist/owasp-api-security-top-10-pt-br.pdf

[^16]: https://checkmarx.com/glossary/

[^17]: https://checkmarx.com/glossary/

[^18]: https://www.bibliotecadeseguranca.com.br/wp-content/uploads/2020/08/glossario-de-seguranca-da-informacao.pdf

[^19]: https://www.cloudflare.com/pt-br/learning/security/threats/owasp-top-10/

[^20]: https://www.verimatrix.com/cybersecurity/glossary/

[^21]: https://www.bibliotecadeseguranca.com.br/wp-content/uploads/2020/08/glossario-de-seguranca-da-informacao.pdf

[^22]: https://owasp.org/API-Security/editions/2019/pt-BR/0x01-about-owasp/

[^23]: https://www.appsecengineer.com/blog/application-security-and-types

[^24]: https://king.host/wiki/artigo/glossario-de-seguranca-web/

[^25]: https://www.vpnunlimited.com/pt/help/cybersecurity/owasp

[^26]: https://www.internetmatters.org/pt/resources/glossary/

[^27]: https://www.softwall.com.br/blog/appsec-como-aplicar-processo-desenvolvimento/

[^28]: https://www.akamai.com/pt/glossary/what-is-owasp

[^29]: https://www.f5.com/es_es/glossary/owasp

[^30]: https://www.gov.br/esporte/pt-br/acesso-a-informacao/lgpd/glossario-de-termos-tecnicos-da-lgpd

[^31]: https://www.convisoappsec.com/glossario/appsec

[^32]: https://www.convisoappsec.com/pt-br/glossario-appsec

[^33]: https://owasp.org/Top10/es/

[^34]: http://www.cncs.gov.pt/pt/glossario

[^35]: https://www.checkpoint.com/pt/cyber-hub/cloud-security/what-is-application-security-appsec/

[^36]: https://www.atatus.com/glossary/application-security/amp/

[^37]: https://checkmarx.com/glossary/application-security-appsec/

[^38]: https://privacy.commonsense.org/resource/infosec-primer/glossary

[^39]: https://www.sumologic.com/glossary/application-security/

[^40]: https://securityboulevard.com/2019/04/web-application-firewalls-101-keywords-to-bookmark/

[^41]: https://blog.devolutions.net/2022/09/new-it-security-glossary-of-terms/

[^42]: http://www.webappsec.org/projects/glossary/

[^43]: https://www.indusface.com/blog/10-popular-application-security-terms-mean/

[^44]: https://devolutions.net/it-security-glossary/

[^45]: http://projects.webappsec.org/w/page/13246967/The Web Security Glossary

[^46]: https://research.cs.wisc.edu/mist/SoftwareSecurityCourse/Chapters/0-Glossary.pdf

[^47]: https://www.indusface.com/news/10-popular-application-and-security-terms-you-should-know/

[^48]: https://digital.ai/pt/glossary/web-application-security/

[^49]: https://www.convisoappsec.com/pt-br/recursos

[^50]: https://www.tecmundo.com.br/ciberseguranca-hp/227094-virus-ransomware-worm-47-termos-seguranca-voce-tem-que-conhecer.htm

[^51]: https://www.tjsc.jus.br/web/tecnologia-da-informacao/glossario-de-seguranca-da-informacao

[^52]: https://play.google.com/store/apps/details?id=com.porolingo.pvocaflashcard

[^53]: https://www.checkpoint.com/pt/cyber-hub/cloud-security/what-is-application-security-appsec/owasp-top-10-vulnerabilities/

[^54]: https://www.akamai.com/pt/glossary

[^55]: https://guiadoestudante.abril.com.br/estudo/9-aplicativos-gratuitos-para-estudar-portugues/

[^56]: https://www.gatinfosec.com/blog/seguranca-de-aplicacoes-gestao-appsec-com-owasp-asvs

[^57]: https://www.gov.br/gsi/pt-br/ssic/glossario-de-seguranca-da-informacao-1

[^58]: https://eval.digital/blog/seguranca-de-api/o-que-e-appsec-e-qual-a-sua-importancia-na-nuvem/

[^59]: https://blog.convisoappsec.com/design-segundo-samm-modelagem-de-ameacas-em-seguranca-de-aplicacoes/

[^60]: https://xygeni.io/pt/sscs-glossary/what-is-application-security-appsec/

[^61]: https://pt.linkedin.com/pulse/guia-completo-dos-cheat-sheets-famosas-colinhas-domine-renato-ribeiro-rqcgf

[^62]: https://www.ovhcloud.com/pt/learn/what-is-application-security/

[^63]: https://www.cyberout.com.br/blog/2/appsec-devsecops

[^64]: https://www.reddit.com/r/cybersecurity/comments/rb035f/anyone_in_appsec_application_security/?tl=pt-br

[^65]: https://blog.convisoappsec.com/afinal-o-que-e-seguranca-de-aplicacoes/

[^66]: https://handbook.vantico.com.br/plataforma/comece-aqui/especifique-os-detalhes-do-pentest/glossario

[^67]: https://www.edgarcosta.net/cheat-sheets/

[^68]: https://partnerstack.com/glossary/app-security-appsec

[^69]: https://security.uconn.edu/glossary/

[^70]: https://www.contabeis.com.br/noticias/51383/glossario-com-os-principais-termos-da-seguranca-digital/

[^71]: https://www.sicoob.com.br/web/sicoobcoomperj/glossario-seguranca-digital

[^72]: https://www.opservices.com.br/glossario-da-cyber-security/

[^73]: https://owasp.org/www-project-developer-guide/release-pt-br/implementação/documentação/série_folha_dicas/

[^74]: https://cheatsheetseries.owasp.org/index.html

[^75]: https://pt.linkedin.com/advice/0/how-do-you-apply-owasp-cheat-sheet-series-your?lang=pt

[^76]: https://snyk.io/pt-BR/solutions/application-security/

[^77]: https://blog.nuneshiggs.com/owasp-cheat-sheet-series-quem-nao-gosta-de-cabulas-rapidas-e-bem-feitas/

[^78]: https://nova8.com.br/o-que-e-appsec-e-sua-importancia/

[^79]: https://play.google.com/store/apps/details?id=com.mobinx.cheatsheet
