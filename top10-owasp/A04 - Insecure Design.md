# A04 - Insecure Design

## Resumo

Nem mesmo é um eror, é uma falha, uma falta de cuidado com decisões grosseieros sem se preocupar com design ou arquitetura de sistema
## Links

Leia mais os linsk a seguir
+ https://brackish.io/2023/09/25/owasp-top-ten-insecure-design/
+ https://blog.codacy.com/insecure-design-owasp-top-1
+ https://codelivly.com/insecure-design/

## Outros

### Best Practices for Secure Design

Link: https://brackish.io/2023/09/25/owasp-top-ten-insecure-design/

+ Least Privilege Access: Design your system so that users and components have only the minimum levels of access — or permissions — they need to accomplish their tasks.
+ Regular Audits: Implement a robust auditing and monitoring system to detect any unauthorized access or anomalies.
Incorporate Security Early: Make security a part of the Software Development Life Cycle (SDLC), not just an afterthought. Perform threat modelling and design review early and often.
+ Penetration Testing: Regular penetration tests will help you identify vulnerabilities.

## Owasp


## Visão Geral

Uma nova categoria para 2021 concentra-se nos riscos relacionados a falhas de design e arquitetura, com uma chamada para mais uso de modelagem de ameaças (_threat modeling_), padrões de design seguros e arquiteturas de referência. Como uma comunidade, precisamos ir além de "_shift-left_" no espaço de codificação para atividades antes da codificação que são críticas para os princípios de  _Secure by Design_. 
+ Notáveis Common Weakness Enumerations (CWEs) incluídas são  _CWE-209: Geração de Mensagem de Erro Contendo Informações Confidenciais_,  _CWE-256: Armazenamento Desprotegido de Credenciais_,  _CWE-501: Violação de Limites de Confiança_  e  _CWE-522: Credenciais Insuficientemente Protegidas_.

## Descrição

O design inseguro é uma categoria ampla que representa diferentes pontos fracos, expressos como "design de controle ausente ou ineficaz". O design inseguro não é a fonte de todas as outras 10 categorias principais de risco de segurança. Há uma diferença entre design inseguro e implementação insegura. Nós diferenciamos entre falhas de design e defeitos de implementação por um motivo, eles têm diferentes causas raízes e remediação. Um design seguro ainda pode ter defeitos de implementação que levam a vulnerabilidades que podem ser exploradas. Um design inseguro não pode ser corrigido por uma implementação perfeita, pois, por definição, os controles de segurança necessários nunca foram criados para a defesa contra ataques específicos. Um dos fatores que contribuem para um design inseguro é a falta de perfis de risco de negócios inerentes ao software ou sistema que está sendo desenvolvido e, portanto, a falha em determinar o nível de design de segurança necessário.

### Gerenciamento de Requisitos e Recursos

Colete e negocie os requisitos de negócios para uma aplicação com a empresa, incluindo os requisitos de proteção relativos à confidencialidade, integridade, disponibilidade e autenticidade de todos os ativos de dados e a lógica de negócios esperada. Leve em consideração a exposição da sua aplicação e se você precisa de segregação de tenants (além do controle de acesso). Compile os requisitos técnicos, incluindo requisitos de segurança funcionais e não funcionais. Planeje e negocie o orçamento cobrindo todo o projeto, construção, teste e operação, incluindo atividades de segurança.

### Design Seguro

O design seguro é uma cultura e metodologia que avalia constantemente as ameaças e garante que o código seja desenvolvido e testado de forma robusta para evitar métodos de ataque conhecidos. A Modelagem de Ameaças deve ser integrada às sessões de refinamento (ou atividades semelhantes); procure por mudanças nos fluxos de dados e controle de acesso ou outros controles de segurança. No desenvolvimento da história do usuário, determine o fluxo correto e os estados de falha, certifique-se de que sejam bem compreendidos e aceitos pelas partes responsáveis e afetadas. Analise suposições e condições para fluxos esperados e de falha, assegure-se de que eles ainda sejam precisos e desejáveis. Determine como validar as suposições e fazer cumprir as condições necessárias para comportamentos adequados. Certifique-se de que os resultados sejam documentados na história do usuário. Aprenda com os erros e ofereça incentivos positivos para promover melhorias. O design seguro não é um  _add-on_  nem uma ferramenta que você pode adicionar ao software.

### Ciclo de Vida de Desenvolvimento Seguro

O software seguro requer um ciclo de vida de desenvolvimento seguro, alguma forma de padrão de projeto seguro, metodologia de  _paved road_, bibliotecas de componentes protegidos, ferramentas e modelagem de ameaças. Procure seus especialistas em segurança no início de um projeto de software, durante todo o projeto e durante a manutenção de seu software. Considere aproveitar o  [OWASP Software Assurance Maturity Model (SAMM)](https://owaspsamm.org/)  para ajudar a estruturar seus esforços de desenvolvimento de software seguro.

## Como Prevenir

-   Estabeleça e use um ciclo de vida de desenvolvimento seguro com profissionais de AppSec para ajudar a avaliar e projetar controles relacionados à segurança e privacidade.
    
-   Estabeleça e use bibliotecas de padrões de projeto seguros ou componentes de  _paved road_  prontos para usar.
    
-   Use Modelagem de Ameaças para autenticação crítica, controle de acesso, lógica de negócios e fluxos de chaves.
    
-   Integre a linguagem e os controles de segurança às histórias de usuários.
    
-   Integre verificações de plausibilidade em cada camada da sua aplicação (do front-end ao back-end).
    
-   Escreva testes de unidade e integração para validar se todos os fluxos críticos são resistentes ao modelo de ameaça. Compile casos de uso de sucesso e casos de uso indevido para cada camada da sua aplicação.
    
-   Separe as camadas de nível no sistema e nas camadas de rede, dependendo das necessidades de exposição e proteção.
    
-   Separe os  _tenants_  de maneira robusta por design em todas as camadas.
    
-   Limite o consumo de recursos por usuário ou serviço.
    

## Exemplos de Cenários de Ataque

**Cenário #1:**  Um fluxo de trabalho de recuperação de credencial pode incluir "perguntas e respostas" (confirmação positiva), o que é proibido pelo NIST 800-63b, o OWASP ASVS e o OWASP Top 10. Perguntas e respostas não podem ser consideradas evidências de identidade, pois mais de uma pessoa pode saber as respostas, é por isso que eles são proibidos. Esse código deve ser removido e substituído por um design mais seguro.

**Cenário #2:**  Uma rede de cinemas permite descontos para reservas de grupos e tem um máximo de quinze participantes antes de exigir um depósito. Os invasores podem modelar esse fluxo e testar se conseguem reservar seiscentos lugares e todos os cinemas de uma só vez em algumas solicitações, causando uma enorme perda de receita.

**Cenário #3:**  O site de comércio eletrônico de uma rede de varejo não tem proteção contra bots executados por cambistas que compram placas de vídeo de última geração para revender sites de leilão. Isso cria uma publicidade terrível para os fabricantes de placas de vídeo e proprietários de redes de varejo, além de sofrer com os entusiastas que não podem obter essas placas a qualquer preço. O design anti-bot cuidadoso e as regras de lógica de domínio, como compras feitas dentro de alguns segundos de disponibilidade, podem identificar compras não autênticas e rejeitar tais transações.

## Referências

-   [OWASP Cheat Sheet: Secure Design Principles](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html)
    
-   [OWASP SAMM: Design:Security Architecture](https://owaspsamm.org/model/design/security-architecture/)
    
-   [OWASP SAMM: Design:Threat Assessment](https://owaspsamm.org/model/design/threat-assessment/)
    
-   [NIST – Guidelines on Minimum Standards for Developer Verification of Software](https://www.nist.gov/publications/guidelines-minimum-standards-developer-verification-software)
    
-   [The Threat Modeling Manifesto](https://threatmodelingmanifesto.org/)
    
-   [Awesome Threat Modeling](https://github.com/hysnsec/awesome-threat-modelling)
    

## Lista dos CWEs Mapeados

[CWE-73 External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)

[CWE-183 Permissive List of Allowed Inputs](https://cwe.mitre.org/data/definitions/183.html)

[CWE-209 Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)

[CWE-213 Exposure of Sensitive Information Due to Incompatible Policies](https://cwe.mitre.org/data/definitions/213.html)

[CWE-235 Improper Handling of Extra Parameters](https://cwe.mitre.org/data/definitions/235.html)

[CWE-256 Unprotected Storage of Credentials](https://cwe.mitre.org/data/definitions/256.html)

[CWE-257 Storing Passwords in a Recoverable Format](https://cwe.mitre.org/data/definitions/257.html)

[CWE-266 Incorrect Privilege Assignment](https://cwe.mitre.org/data/definitions/266.html)

[CWE-269 Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)

[CWE-280 Improper Handling of Insufficient Permissions or Privileges](https://cwe.mitre.org/data/definitions/280.html)

[CWE-311 Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)

[CWE-312 Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)

[CWE-313 Cleartext Storage in a File or on Disk](https://cwe.mitre.org/data/definitions/313.html)

[CWE-316 Cleartext Storage of Sensitive Information in Memory](https://cwe.mitre.org/data/definitions/316.html)

[CWE-419 Unprotected Primary Channel](https://cwe.mitre.org/data/definitions/419.html)

[CWE-430 Deployment of Wrong Handler](https://cwe.mitre.org/data/definitions/430.html)

[CWE-434 Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)

[CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')](https://cwe.mitre.org/data/definitions/444.html)

[CWE-451 User Interface (UI) Misrepresentation of Critical Information](https://cwe.mitre.org/data/definitions/451.html)

[CWE-472 External Control of Assumed-Immutable Web Parameter](https://cwe.mitre.org/data/definitions/472.html)

[CWE-501 Trust Boundary Violation](https://cwe.mitre.org/data/definitions/501.html)

[CWE-522 Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)

[CWE-525 Use of Web Browser Cache Containing Sensitive Information](https://cwe.mitre.org/data/definitions/525.html)

[CWE-539 Use of Persistent Cookies Containing Sensitive Information](https://cwe.mitre.org/data/definitions/539.html)

[CWE-579 J2EE Bad Practices: Non-serializable Object Stored in Session](https://cwe.mitre.org/data/definitions/579.html)

[CWE-598 Use of GET Request Method With Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html)

[CWE-602 Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)

[CWE-642 External Control of Critical State Data](https://cwe.mitre.org/data/definitions/642.html)

[CWE-646 Reliance on File Name or Extension of Externally-Supplied File](https://cwe.mitre.org/data/definitions/646.html)

[CWE-650 Trusting HTTP Permission Methods on the Server Side](https://cwe.mitre.org/data/definitions/650.html)

[CWE-653 Insufficient Compartmentalization](https://cwe.mitre.org/data/definitions/653.html)

[CWE-656 Reliance on Security Through Obscurity](https://cwe.mitre.org/data/definitions/656.html)

[CWE-657 Violation of Secure Design Principles](https://cwe.mitre.org/data/definitions/657.html)

[CWE-799 Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html)

[CWE-807 Reliance on Untrusted Inputs in a Security Decision](https://cwe.mitre.org/data/definitions/807.html)

[CWE-840 Business Logic Errors](https://cwe.mitre.org/data/definitions/840.html)

[CWE-841 Improper Enforcement of Behavioral Workflow](https://cwe.mitre.org/data/definitions/841.html)

[CWE-927 Use of Implicit Intent for Sensitive Communication](https://cwe.mitre.org/data/definitions/927.html)

[CWE-1021 Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html)

[CWE-1173 Improper Use of Validation Framework](https://cwe.mitre.org/data/definitions/1173.html)

## ChatGPT

### Q1 

> Fale soA04 Insecure Design do OWASP

O **OWASP A04:2021 – Insecure Design** (Design Inseguro) é a quarta categoria da lista OWASP Top 10 de 2021, que trata das **falhas de segurança resultantes de decisões inadequadas no design ou arquitetura de software**, independentemente de erros de implementação posteriores.

### 🧠 O que é o "Insecure Design"?

É quando um sistema é construído sem considerar princípios de segurança desde o início. Não se trata de bugs ou vulnerabilidades específicas de código, mas sim de **decisões estruturais erradas** que colocam a aplicação em risco.

#### Exemplos:

* Ausência de **limites de taxa (rate limiting)** em funcionalidades sensíveis como login ou APIs.
* Projetos que não separam **funções críticas** (como administrativo e usuário comum).
* Fluxos que permitem **ataques de força bruta ou scraping** por não terem proteções suficientes.
* Falta de **modelagem de ameaças** para identificar riscos nos fluxos de negócio.
* Aplicações que assumem que o front-end é confiável e não validam regras de negócio no back-end.

---

### ⚠️ Consequências

Um design inseguro pode levar a:

* **Escalada de privilégios**
* **Vazamento de dados sensíveis**
* **Ataques automatizados (bots, scraping, brute force)**
* **Abuso de funcionalidades legítimas**

---

### 🛠️ Como prevenir?

* **Modelagem de ameaças** desde as fases iniciais do projeto.
* **Segurança por design**: aplicar princípios como *least privilege*, *defense in depth*, *fail-safe defaults*.
* Criar e aplicar **testes de segurança em nível de arquitetura**.
* Simular abusos de lógica de negócios e analisar os fluxos.
* Ter documentação clara das **regras de segurança do sistema**.

---

### Exemplo prático

Imagine uma aplicação de transferências bancárias que **não limita o número de tentativas** de envio por segundo. Mesmo que cada tentativa valide o saldo, um atacante pode automatizar milhares de requisições por segundo e causar problemas (como DDOS financeiro, uso indevido ou vazamento de informações). Isso é falha de **design inseguro**, pois a arquitetura não considerou esse risco desde o início.

---

Quer que eu aplique esse conceito a um caso específico do seu projeto?


### Q2

> Pesquise na web e me informe exempls de casos de design insrguros

Claro! A seguir, apresento exemplos reais e cenários práticos que ilustram falhas de **design inseguro** (OWASP A04:2021 – Insecure Design), demonstrando como decisões inadequadas na arquitetura de sistemas podem comprometer a segurança de aplicações:

---

### 🔐 Exemplos Reais de Design Inseguro

#### 1. **Vazamento de Dados da Ashley Madison (2015)**

O site Ashley Madison, voltado para relacionamentos extraconjugais, sofreu um ataque que expôs dados sensíveis de milhões de usuários.

* **Falha de design**: Armazenamento inadequado de informações sensíveis, como nomes reais e detalhes de pagamento, sem criptografia robusta ou políticas de retenção de dados adequadas.
* **Consequência**: Exposição massiva de dados pessoais, resultando em danos à reputação e processos legais. ([Brackish Security][1])

#### 2. **Vazamento de Dados da Equifax (2017)**

A Equifax, uma das maiores agências de crédito dos EUA, teve informações pessoais de aproximadamente 147 milhões de pessoas comprometidas.

* **Falha de design**: Ausência de mecanismos eficazes de monitoramento e atualização, permitindo a exploração de uma vulnerabilidade conhecida no Apache Struts.
* **Consequência**: Perda de dados sensíveis, multas significativas e danos à confiança dos consumidores. ([blog.codacy.com][2])

#### 3. **Vulnerabilidade Heartbleed no OpenSSL (2014)**

Uma falha no OpenSSL permitia que atacantes lessem informações sensíveis da memória de servidores.

* **Falha de design**: Falta de validação adequada de entradas no processamento de solicitações "heartbeat", resultando em leitura indevida de memória.
* **Consequência**: Exposição de chaves privadas, senhas e outros dados críticos. ([codelivly.com][3], [vumetric.com][4], [OWASP][5])

---

### 🧪 Cenários Práticos de Design Inseguro

#### 4. **Recuperação de Senha com Perguntas e Respostas**

Implementar recuperação de senha baseada em perguntas como "Qual o nome do seu primeiro animal de estimação?" é inseguro.

* **Falha de design**: Essas perguntas são facilmente descobertas ou adivinhadas, não fornecendo autenticação confiável.
* **Consequência**: Facilidade para atacantes resetarem senhas de usuários legítimos.&#x20;

#### 5. **Reserva de Ingressos sem Limites Adequados**

Um sistema de reservas que permite múltiplas reservas sem verificação adequada pode ser explorado.

* **Falha de design**: Ausência de limites de quantidade ou validações por usuário.
* **Consequência**: Atacantes podem reservar grandes quantidades de ingressos, causando perdas financeiras.&#x20;

#### 6. **Exposição de Dados Sensíveis via URLs**

Incluir informações sensíveis em parâmetros de URL (método GET) pode levar à exposição de dados.

* **Falha de design**: Dados como logins ou tokens de sessão podem ser armazenados em logs de servidores ou históricos de navegadores.
* **Consequência**: Potencial vazamento de informações confidenciais.&#x20;

---

### ✅ Boas Práticas para Prevenir Design Inseguro

* **Modelagem de Ameaças**: Identificar e mitigar riscos desde as fases iniciais do desenvolvimento.
* **Princípios de Segurança**: Aplicar conceitos como "privilégio mínimo" e "defesa em profundidade".
* **Validações no Lado do Servidor**: Não confiar apenas em validações do lado do cliente.
* **Criptografia Adequada**: Proteger dados sensíveis em repouso e em trânsito.
* **Testes de Segurança**: Realizar testes regulares para identificar e corrigir vulnerabilidades.([blog.codacy.com][2])

Se desejar, posso ajudar a analisar o design de um sistema específico ou fornecer orientações para fortalecer a segurança de sua aplicação.

[1]: https://brackish.io/owasp-top-ten-insecure-design/?utm_source=chatgpt.com "OWASP Top Ten - Insecure Design - Brackish Security"
[2]: https://blog.codacy.com/insecure-design-owasp-top-10?utm_source=chatgpt.com "Insecure Design: A Complete Guide"
[3]: https://www.codelivly.com/insecure-design/?utm_source=chatgpt.com "OWASP Top Ten: Insecure Design Vulnerabilities – Codelivly"
[4]: https://www.vumetric.com/blog/owasp-top-10-a04-insecure-design-everything-you-need-to-know/?utm_source=chatgpt.com "OWASP A04 Insecure Design: Risks, Examples, and Prevention - Vumetric"
[5]: https://owasp.org/Top10/it/A04_2021-Insecure_Design/?utm_source=chatgpt.com "A04 Insecure Design - OWASP Top 10:2021"




## Perplexity

<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" class="logo" width="120"/>

# A04: Design Inseguro - Conceito e Exemplos em Aplicações Web

O Design Inseguro representa uma nova e importante categoria introduzida na lista OWASP Top 10 de 2021, focando nos problemas fundamentais de segurança que ocorrem na fase de arquitetura e planejamento de sistemas, antes mesmo da implementação do código.

## O que é Design Inseguro

Design Inseguro ocorre quando a segurança não é considerada desde o início do processo de desenvolvimento de software. Esta categoria se concentra nas falhas de design e nos riscos associados a essas falhas, diferente dos problemas de implementação que frequentemente se encaixam em outras categorias de segurança[^15]. A OWASP introduziu esta categoria visando promover princípios de design mais seguros e consistentes, padrões e arquiteturas de referência que garantam a estabilidade e segurança dos dados em aplicações web[^15].

O Design Inseguro acontece quando a segurança não é parte integrante do processo de planejamento, resultando em falhas que se tornam difíceis de corrigir posteriormente no ciclo de desenvolvimento[^16]. Este tipo de vulnerabilidade é particularmente preocupante porque, mesmo com uma implementação tecnicamente perfeita, um sistema baseado em um design inseguro continuará vulnerável a ataques.

### Como o Design Inseguro difere de outras falhas de segurança

Enquanto muitas categorias do OWASP Top 10 focam em vulnerabilidades técnicas específicas (como injeção ou falhas criptográficas), o Design Inseguro aborda a segurança de forma mais holística[^15]. Essa categoria visa encontrar e corrigir falhas fundamentais na arquitetura e no design do sistema, em vez de problemas na implementação do código. Um sistema pode ter um código perfeitamente escrito, sem vulnerabilidades tradicionais, mas ainda assim ser fundamentalmente inseguro devido a decisões de design inadequadas.

## Exemplos de Design Inseguro em Aplicações Web

### 1. Limitação de Taxa Ineficaz

Um exemplo notável ocorreu no Facebook no início de 2021, quando um grande volume de dados pessoais foi vazado. Este incidente foi causado por limites de taxa e limites de dados ineficazes implementados pela plataforma, que permitiram acesso excessivo aos dados usando ferramentas automatizadas[^14]. Esse problema de design facilita técnicas de "scraping" em massa, onde atacantes podem extrair quantidades enormes de dados sem serem detectados ou bloqueados.

### 2. Falta de Proteção Contra Bots em E-commerce

Um exemplo comum é o de sites de comércio eletrônico de redes de varejo que não possuem proteção contra bots executados por atacantes[^18]. Isso permite que os invasores realizem compras automatizadas de produtos em alta demanda (como ingressos para eventos, tênis de edição limitada ou consoles de videogame), esgotando o estoque antes que clientes legítimos possam fazer suas compras. Este é um problema de design porque o sistema foi concebido sem considerar este cenário de ataque.

### 3. Arquitetura de Aplicação Sem Segregação de Dados

Uma aplicação web que armazena dados sensíveis (como informações de pagamento) no mesmo banco de dados que informações menos críticas, sem a devida segregação, apresenta um design inseguro. Se um invasor conseguir acesso ao banco de dados através de qualquer vulnerabilidade, ele terá acesso a todos os dados, incluindo os mais sensíveis.

### 4. Falha na Modelagem de Ameaças

Sistemas que são desenvolvidos sem um processo formal de modelagem de ameaças frequentemente falham em considerar cenários de ataque críticos. Por exemplo, uma aplicação de saúde que não considera os riscos associados à exposição de dados de pacientes pode ser projetada sem os controles de acesso granulares necessários, resultando em potenciais violações de privacidade.

### 5. Processos de Recuperação de Conta Mal Projetados

Sistemas de recuperação de senha que dependem apenas de informações facilmente descobertas (como "qual é o nome do seu pet?") representam um design inseguro. Este tipo de falha permitiu, em casos famosos, que contas de celebridades e figuras públicas fossem comprometidas através de engenharia social simples.

## Como Prevenir o Design Inseguro

Para mitigar os riscos associados ao design inseguro, recomenda-se:

1. Incorporar modelagem de ameaças e princípios de "secure-by-design" desde o início do desenvolvimento[^16].
2. Utilizar ciclos de vida de desenvolvimento seguro (SDL) que incluam revisões regulares de segurança durante todas as fases do projeto[^14].
3. Implementar padrões de design seguros e arquiteturas de referência que já considerem potenciais ameaças[^15].
4. Revisar regularmente o design do sistema para identificar potenciais vulnerabilidades antes que se tornem problemas sérios[^16].
5. Utilizar ferramentas de Application Security Posture Management (ASPM) para identificar falhas de design em estágios iniciais[^16].
6. Implementar limites de taxa e monitoramento de comportamento para detectar padrões de uso anômalos que possam indicar tentativas de abuso.

## Conclusão

O Design Inseguro representa uma abordagem fundamentalmente falha no desenvolvimento de software, onde os aspectos de segurança não são considerados desde a concepção do sistema. Diferente de outras vulnerabilidades que podem ser corrigidas com patches ou atualizações de código, os problemas de design inseguro frequentemente exigem reestruturações significativas ou redesenho completo de sistemas.

Para desenvolvedores e organizações, é crucial adotar uma mentalidade de "security by design", onde a segurança é uma consideração primária desde os estágios iniciais de planejamento. Implementar modelagem de ameaças, arquiteturas de referência seguras e revisões regulares de design pode ajudar a evitar as armadilhas associadas ao design inseguro, resultando em aplicações web mais robustas e resistentes a ataques.

<div style="text-align: center">⁂</div>

[^1]: https://owasp.org/Top10/

[^2]: https://blog.convisoappsec.com/pesquisa-cve-2021-43076-e-os-riscos-causados-pelo-insecure-design/

[^3]: https://www.vumetric.com/blog/owasp-top-10-a04-insecure-design-everything-you-need-to-know/

[^4]: https://owasp.org/Top10/pt_BR/A04_2021-Insecure_Design/

[^5]: https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Status/501

[^6]: https://www.cvedetails.com/cve/CVE-2021-43076

[^7]: https://owasp.org/Top10/A04_2021-Insecure_Design/

[^8]: https://owasp.org/www-project-top-ten/

[^9]: https://dev.to/gabogaldino/explicando-o-top-4-da-owasp-design-inseguro-para-desenvolvedores-4lf0

[^10]: https://www.clouddefense.ai/cve/2021/CVE-2021-43076

[^11]: https://www.checkpoint.com/pt/cyber-hub/cloud-security/what-is-application-security-appsec/owasp-top-10-vulnerabilities/

[^12]: https://blog.convisoappsec.com/en/research-cve-2021-43076-and-the-risks-caused-by-insecure-design/

[^13]: https://www.hkcert.org/blog/owasp-top-10-2021-is-now-released

[^14]: https://www.estrategiaconcursos.com.br/blog/10-riscos-seguranca-web-owasp/

[^15]: https://www.youtube.com/watch?v=bbmplrUG5Nc

[^16]: https://xygeni.io/pt/blog/owasp-top-10-and-their-remedies/

[^17]: https://www.sapphire.net/blogs-press-releases/owasp-top-10/

[^18]: https://www.dio.me/articles/owasp-principais-vulnerabilidades-e-remediacoes-mapeadas

[^19]: https://dev.to/gabogaldino/explicando-o-top-4-da-owasp-design-inseguro-para-desenvolvedores-4lf0

[^20]: https://www.jerkeby.se/newsletter/posts/business-logic/

[^21]: https://cwe.mitre.org/data/definitions/1348.html

[^22]: https://blog.convisoappsec.com/owasp-top-10-como-aplicar/

[^23]: https://pt.linkedin.com/pulse/insegurança-em-design-a04-owasp-top-10-ivan-grand-champs-pereira-cckrf

[^24]: https://www.youtube.com/watch?v=lrL1zcesmOI

[^25]: https://www.eldorado.org.br/blog/boas-praticas-em-cyber-security-para-aplicacoes-web/

[^26]: https://www.nearform.com/insights/owasp-top-ten-workshop/

[^27]: https://www.youtube.com/watch?v=foaBmTvRrJw

[^28]: https://nearform.com/insights/owasp-top-ten-workshop/

[^29]: https://owasp.org/Top10/pt_BR/A04_2021-Insecure_Design/

[^30]: https://hackersec.com/conheca-owasp-top-10-as-principais-vulnerabilidades-web/

[^31]: https://www.ibm.com/br-pt/think/topics/cve

[^32]: https://www.verifact.com.br/wp-content/uploads/2022/07/WEB_Report_Penetration_Test_Verifact_Gray_Box_Publicacao.pdf

[^33]: https://cwe.mitre.org/data/definitions/501.html

[^34]: https://www.cloudflare.com/pt-br/learning/security/threats/owasp-top-10/

[^35]: https://www.welivesecurity.com/pt/vulnerabilidades/as-10-principais-vulnerabilidades-criticas-em-aplicativos-da-web-destacadas-pela-owasp/

[^36]: https://repositorio.ufu.br/bitstream/123456789/38406/1/EstudoVulnerabilidadesOWASP.pdf

[^37]: https://www.siteblindado.com/blog/single-post/owasp-top-10

[^38]: https://accesssecurity.com.br/owasp-top-ten-2021/

[^39]: https://stackoverflow.com/questions/44818342/how-to-resolve-cwe-id-501-trust-boundary-violation

[^40]: https://pt.linkedin.com/pulse/design-inseguro-em-segurança-da-informação-e-aplicações-l-s--ndeff

[^41]: https://www.incibe.es/index.php/en/incibe-cert/early-warning/vulnerabilities/cve-2021-43076

[^42]: https://aspiainfotech.com/2022/12/12/insecure-designs-vulnerability/

[^43]: https://nvd.nist.gov/vuln/cvmap/report/7960

[^44]: https://cwe.mitre.org/data/definitions/256.html

[^45]: https://www.security-database.com/view-all.php?page=5714

[^46]: https://cwe.mitre.org/data/definitions/1344.html

[^47]: https://nvd.nist.gov/vuln/cvmap/report/8679

[^48]: https://nvd.nist.gov/vuln/detail/CVE-2024-3082

[^49]: https://nvd.nist.gov/vuln/detail/CVE-2021-43076

[^50]: https://github.com/advisories/GHSA-vcjf-q2w8-qgmr

[^51]: https://blog.convisoappsec.com/pesquisa-cve-2021-43076-e-os-riscos-causados-pelo-insecure-design/

