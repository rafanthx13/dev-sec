# A08 - Software and Data Integrity Failures

## Resumo

Uma falha de integridade ocorre quando algo é modificado de forma maliciosa sem que ninguém perceba. A falha mais comum acontece ao utilizar dependências de terceiros, como bibliotecas (libs) e o processo de CI/CD (Integração Contínua/Entrega Contínua). Se você baixar uma biblioteca no dia X e, em uma atualização futura (dia N), essa biblioteca não for proveniente de uma fonte confiável, ela pode conter código malicioso capaz de roubar seus dados. Um pipeline de CI/CD inseguro pode se tornar uma porta dos fundos (backdoor): mesmo que seu código esteja correto, a versão de produção pode ser adulterada com um backdoor. Portanto, é necessário ter maior cuidado ao atualizar dependências e garantir a integridade do pipeline de CI/CD, além de verificar quem realmente tem permissão para alterá-lo.

## Links

+ https://medium.com/@madhuhack01/owasp-top-10-a08-2021-owasp-top-10-a08-2021-software-and-data-integrity-failures-df5ab1396f5e

## OWASP

### Descrição

Falhas na integridade de software e dados estão relacionadas a código e infraestrutura que não protegem contra violações de integridade. Um exemplo disso é quando um aplicativo depende de plugins, bibliotecas ou módulos de fontes, repositórios e redes de entrega de conteúdo (CDNs) não confiáveis. Um pipeline de CI/CD inseguro pode introduzir a possibilidade de acesso não autorizado, código malicioso ou comprometimento do sistema. Por último, muitos aplicativos agora incluem funcionalidade de atualização automática, onde as atualizações são baixadas sem verificação de integridade suficiente e aplicadas ao aplicativo previamente confiável. Atacantes podem potencialmente fazer upload de suas próprias atualizações para serem distribuídas e executadas em todas as instalações. Outro exemplo é quando objetos ou dados são codificados ou serializados em uma estrutura que um atacante pode ver e modificar, o que torna a deserialização insegura.

### Como previinir

+ Use assinaturas digitais ou mecanismos similares para verificar se o software ou os dados são provenientes da fonte esperada e não foram alterados.

+ Certifique-se de que as bibliotecas e dependências, como npm ou Maven, estão consumindo repositórios confiáveis. Se você tiver um perfil de risco mais alto, considere hospedar um repositório interno conhecido como bom que foi examinado.

+ Certifique-se de que uma ferramenta de segurança da cadeia de suprimentos de software, como OWASP Dependency Check ou OWASP CycloneDX, é usada para verificar se os componentes não contêm vulnerabilidades conhecidas.

+ Certifique-se de que haja um processo de revisão para mudanças de código e configuração para minimizar a chance de que código ou configuração maliciosos possam ser introduzidos no seu pipeline de software.

+ Certifique-se de que seu pipeline de CI/CD tenha uma segregação adequada, configuração e controle de acesso para garantir a integridade do código que flui através dos processos de construção e implantação.

+ Certifique-se de que dados serializados não assinados ou não criptografados não sejam enviados a clientes não confiáveis sem algum tipo de verificação de integridade ou assinatura digital para detectar adulteração ou retransmissão dos dados serializados.

## Referencias do owap

Referências
+ [OWASP Cheat Sheet: Software Supply Chain Security](Em breve)

+ [OWASP Cheat Sheet: Secure build and deployment](Em breve)

+ OWASP Cheat Sheet: Infrastructure as Code

+ OWASP Cheat Sheet: Deserialization

+ SAFECode Software Integrity Controls

+ A 'Worst Nightmare' Cyberattack: The Untold Story Of The SolarWinds Hack

+ CodeCov Bash Uploader Compromise

+ Securing DevOps by Julien Vehent

**Lista dos CWEs Mapeados:**

+ CWE-345 Insufficient Verification of Data Authenticity

+ CWE-353 Missing Support for Integrity Check

+ CWE-426 Untrusted Search Path

+ CWE-494 Download of Code Without Integrity Check

+ CWE-502 Deserialization of Untrusted Data

+ CWE-565 Reliance on Cookies without Validation and Integrity Checking

+ CWE-784 Reliance on Cookies without Validation and Integrity Checking in a Security Decision

+ CWE-829 Inclusion of Functionality from Untrusted Control Sphere

+ CWE-830 Inclusion of Web Functionality from an Untrusted Source

+ CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes

---
---
---

## Conversa com ChatGPT

### Q1 - Start A08

> Fale mais sobre A08 do OWASP : Software and Data Integrity Failures

Claro, Rafael! A categoria **A08:2021 - Software and Data Integrity Failures** da OWASP Top 10 trata de falhas relacionadas à **confiança em fontes externas de software, bibliotecas, atualizações e dados sem verificação adequada de integridade**. Isso inclui riscos como injeções maliciosas em bibliotecas, atualizações corrompidas ou manipuladas, e pipelines de CI/CD inseguros.

---

🔍 **O que isso significa na prática?**

Quando uma aplicação:

* Usa **dependências de terceiros** sem validar sua integridade (ex: via hash, assinatura);
* Realiza **atualizações automáticas** de software ou componentes sem verificar a origem e integridade;
* Possui pipelines de **integração e entrega contínua (CI/CD)** mal protegidos;
* Permite que usuários façam upload de arquivos sem checagem de conteúdo ou origem;
* Executa scripts configuráveis (como YAMLs ou JSONs) sem sanitização adequada;

...ela se expõe a ataques como:

* **Ataques à cadeia de suprimentos (supply chain attacks)**;
* **Ataques por bibliotecas maliciosas (ex: npm typosquatting)**;
* **Execução de código remoto** com privilégios da aplicação.

---

🔥 **Exemplos reais**

* Em 2020, o ataque à **SolarWinds** permitiu que agentes maliciosos injetassem código malicioso em atualizações legítimas de software.
* Casos de pacotes maliciosos no **npm**, **PyPI** e outros repositórios, que visam capturar tokens, senhas ou executar comandos remotos.
* Scripts maliciosos injetados em ambientes que executam configurações do tipo YAML ou JSON sem validação.

---

✅ **Como se proteger?**

1. **Verificar assinaturas digitais** de bibliotecas, pacotes e atualizações.
2. Usar **Gerenciadores de Dependência seguros** com *lockfiles* (como `package-lock.json`, `composer.lock`).
3. Ativar e proteger pipelines CI/CD com:

   * Controle de acesso;
   * Variáveis seguras;
   * Auditoria de etapas e histórico.
4. Validar e filtrar cuidadosamente qualquer dado ou arquivo usado para configurar ou atualizar sistemas.
5. Monitorar dependências usando ferramentas como:

   * [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
   * Snyk, Dependabot, Renovate, etc.
6. Implementar políticas de **principle of least privilege** para repositórios e pipelines.

---

Se quiser, posso te mostrar como verificar a integridade de dependências num projeto específico (ex: Laravel, Go, Python). Quer?


## Q2 - Como se proteger no Laravel

> Mostre pra Laravel

Ótimo ponto, Rafael — proteger o CI/CD no **Azure DevOps** é fundamental para evitar falhas de integridade de software (OWASP A08). Como ele controla o que vai para produção, qualquer brecha aqui pode permitir que código malicioso ou alterado seja implantado.

Aqui estão as **principais práticas de segurança para proteger o CI/CD no Azure DevOps**:

---

 🔐 **1. Proteja os `Service Connections` e `Secrets`**

* **Nunca use variáveis sensíveis diretamente em YAML**.
* Use o **Azure Key Vault** integrado com o pipeline para armazenar segredos.
* Use `secrets: true` para evitar que valores apareçam em logs.

**Exemplo:**

```yaml
variables:
  - group: my-secrets-group

steps:
  - script: echo $(DATABASE_PASSWORD)
    displayName: 'Usar variável secreta'
```

---

 🚧 **2. Restrinja quem pode editar pipelines**

* **Configure permissões de segurança** nos repositórios e pipelines:

  * Apenas usuários autorizados podem editar YAML ou pipelines Classic.
  * Use **branch policies** para evitar alterações diretas em `main`/`production`.

---

 🔐 **3. Assine e valide artefatos**

* Se você estiver gerando **pacotes, containers ou arquivos de build**, implemente:

  * **Assinatura digital de artefatos**.
  * Validação de hash no destino (ex: validar que o hash da imagem Docker corresponde ao esperado).

---

 🛡️ **4. Use ambientes protegidos (Environments)**

O Azure DevOps permite que você configure **"Environments"** com **aprovações manuais**, escopo limitado de deploy, e variáveis separadas.

**Vantagens:**

* Controla quem pode fazer deploy.
* Permite configurar *"checks"* (ex: aprovação manual, tempo de espera, etc).

---

 🔄 **5. Use deployment slots no Azure App Service**

Ao usar **Web Apps no Azure**, configure um **slot de staging**:

* Realize o deploy no slot de staging.
* Teste o app.
* Faça o swap para produção **somente após validação**.

Evita que uma build defeituosa afete imediatamente o ambiente de produção.

---

 👀 **6. Habilite logs e auditoria**

* Ative **auditoria no Azure DevOps** para monitorar quem alterou pipelines ou secrets.
* Configure alertas para mudanças inesperadas.

---

 🧪 **7. Execute testes e auditoria automática**

Inclua etapas como:

```yaml
- script: composer audit
  displayName: 'Auditoria de segurança Composer'

- script: php artisan test
  displayName: 'Testes automatizados'
```

E também scanners de segurança como:

* **Snyk**
* **Trivy (para containers)**
* **OWASP Dependency-Check**

---

 🚫 **8. Evite execução remota sem validação**

Se você aceita artefatos externos (como YAMLs, JSONs, arquivos ZIP), **valide bem antes de usar**. Nunca execute comandos diretamente com base nesses arquivos sem verificação.

---

 📌 **9. Sempre fixe as versões de ações e ferramentas**

Evite usar referências do tipo `@latest` ou `@master`. Prefira `@v1.2.3`, para garantir que uma atualização inesperada não quebre ou comprometa seu pipeline.

---

 💡 Exemplo simples de pipeline seguro em Laravel (resumo)

```yaml
trigger:
  branches:
    include:
      - main

variables:
  - group: LaravelSecrets

stages:
  - stage: Build
    jobs:
      - job: ComposerInstall
        steps:
          - task: UsePHP@0
            inputs:
              version: '8.2'

          - script: composer install --no-dev --optimize-autoloader
          - script: composer audit

  - stage: Test
    jobs:
      - job: RunTests
        steps:
          - script: php artisan test

  - stage: Deploy
    dependsOn: Test
    condition: succeeded()
    jobs:
      - deployment: DeployToProd
        environment: 'Production'
        strategy:
          runOnce:
            deploy:
              steps:
                - script: echo "Deploy seguro com aprovação manual"
```

---

Se quiser, posso montar um `azure-pipelines.yml` mais completo para seu projeto Laravel, com deploy para Azure Web App usando slots e chaves do Key Vault. Deseja isso?


### Q4 - Cmo devera ser o `azure-pipelines.yaml`

> Monte um azure-pipelines.yml mais completo e explique bem cada etapa do arquivo

Perfeito, Rafael! Abaixo está um exemplo bem estruturado de um arquivo `azure-pipelines.yml` completo para um **projeto Laravel** com:

* **Build seguro**
* **Testes**
* **Auditoria de dependências**
* **Deploy com aprovação manual**
* **Uso do Key Vault**
* **Deploy com slot de staging**

---

🛠️ `azure-pipelines.yml` COMPLETO (comentado linha a linha)

```yaml
trigger:
  branches:
    include:
      - main  # 🚨 Pipeline só dispara quando a branch 'main' sofre push.

variables:
  - group: LaravelSecrets  # 🔐 Grupo de variáveis (ex: chaves .env) protegidas via Azure Key Vault

stages:
  - stage: Build
    displayName: '🔧 Etapa de Build e Auditoria'
    jobs:
      - job: ComposerAudit
        displayName: '🛠️ Instalação de Dependências e Auditoria'
        pool:
          vmImage: 'ubuntu-latest'
        steps:
          - task: UsePHPVersion@0
            inputs:
              versionSpec: '8.2'
              addToPath: true

          - checkout: self  # 📦 Clona o código do repositório

          - script: |
              composer install --no-dev --optimize-autoloader
            displayName: '📦 Composer Install'

          - script: composer audit
            displayName: '🔍 Composer Audit - Verificação de vulnerabilidades'

          - task: PublishBuildArtifacts@1
            inputs:
              pathToPublish: '$(System.DefaultWorkingDirectory)'
              artifactName: 'laravel-artifacts'
              publishLocation: 'Container'
            displayName: '📤 Publicar artefato para próxima etapa'

  - stage: Test
    displayName: '🧪 Etapa de Testes Automatizados'
    dependsOn: Build
    condition: succeeded()
    jobs:
      - job: RunTests
        displayName: '▶️ PHPUnit Testes'
        pool:
          vmImage: 'ubuntu-latest'
        steps:
          - task: DownloadBuildArtifacts@0
            inputs:
              artifactName: 'laravel-artifacts'
              downloadPath: '$(System.DefaultWorkingDirectory)'

          - script: |
              cp .env.pipelines .env  # 📝 Usa um .env próprio para testes
              php artisan key:generate
            displayName: '⚙️ Preparar .env e chave app'

          - script: php artisan test
            displayName: '🧪 Executar Testes com PHPUnit'

  - stage: Deploy
    displayName: '🚀 Etapa de Deploy'
    dependsOn: Test
    condition: succeeded()
    jobs:
      - deployment: DeployToStaging
        displayName: '📦 Deploy para slot de staging'
        environment: 'production-staging'  # 🌍 Ambiente com aprovação manual no Azure DevOps
        strategy:
          runOnce:
            deploy:
              steps:
                - task: AzureWebApp@1
                  inputs:
                    azureSubscription: 'MinhaConexaoAzure'  # 🔐 Nome do serviço de conexão com Azure
                    appName: 'meu-app-laravel'              # 🌐 Nome do App Service
                    deployToSlotOrASE: true
                    resourceGroupName: 'meu-grupo-rg'
                    slotName: 'staging'                     # 🎯 Slot de staging
                    package: '$(Pipeline.Workspace)/laravel-artifacts'
                  displayName: '🌐 Deploy para Azure App Service (staging)'

      - deployment: SwapSlot
        displayName: '🔁 Promover staging para produção'
        environment: 'production'  # ⚠️ Ambiente real com nova aprovação
        dependsOn: DeployToStaging
        strategy:
          runOnce:
            deploy:
              steps:
                - task: AzureAppServiceManage@0
                  inputs:
                    azureSubscription: 'MinhaConexaoAzure'
                    Action: 'Swap Slots'
                    WebAppName: 'meu-app-laravel'
                    ResourceGroupName: 'meu-grupo-rg'
                    SourceSlot: 'staging'
                    TargetSlot: 'production'
                  displayName: '🚀 Swap staging → produção'
```

---

🧠 EXPLICAÇÃO RESUMIDA POR BLOCOS

| Bloco             | Explicação                                                                                              |
| ----------------- | ------------------------------------------------------------------------------------------------------- |
| `trigger`         | Só inicia o pipeline com push na `main`.                                                                |
| `variables`       | Carrega segredos do Key Vault, como `.env`, senhas etc.                                                 |
| `Build`           | Instala as dependências via `composer`, faz auditoria de segurança e publica os arquivos como artefato. |
| `Test`            | Baixa o artefato e executa `php artisan test` após configurar o ambiente `.env`.                        |
| `DeployToStaging` | Faz deploy em um **slot de staging**, com revisão ou aprovação manual habilitada (recomendado).         |
| `SwapSlot`        | Após a aprovação, troca os slots e promove staging para produção.                                       |
| `environments`    | Usado para aplicar **checks manuais**, escopos de variável, ou limitar quem pode fazer deploy.          |

---

🔒 Segurança e Integridade

* 💼 `Azure Key Vault` garante que senhas/API keys não fiquem no código.
* 🔐 Slots protegem contra deploys diretos em produção.
* ✅ Auditoria de dependências (composer audit) impede que libs vulneráveis passem.
* ⚠️ `environment:` força **aprovadores humanos** antes de deploys críticos.

---

Se quiser, posso adaptar esse YAML para **usar Docker**, **banco de dados MySQL/Azure SQL**, ou incluir integração com **tests no Cypress**, por exemplo. Deseja expandir para algum desses cenários?

## Q4 - O ataque da Solar Wind

> Fale mais sobre o ataque do SolarWind e o relaicone ao A08 do OWASP

O ataque à **SolarWinds** é um dos exemplos mais emblemáticos de falha de integridade de software — exatamente o que o OWASP classifica como **A08:2021 – Software and Data Integrity Failures**.

---

**🕵️‍♂️ O que foi o ataque à SolarWinds?**

📌 Contexto

A SolarWinds é uma empresa que desenvolve software de monitoramento de infraestrutura, incluindo o **Orion Platform**, usado por milhares de organizações privadas e públicas, inclusive o governo dos EUA.

🎯 O que aconteceu?

Em 2020, invasores conseguiram **inserir código malicioso** diretamente no build do Orion (um tipo de "backdoor"), em uma das versões oficiais distribuídas aos clientes.

Esse código foi entregue como parte do **update legítimo** do software — ou seja, os próprios clientes instalaram a porta de entrada para o ataque acreditando estar apenas atualizando o sistema.

---

🔍 Técnica usada: **Ataque à Cadeia de Suprimentos (Supply Chain Attack)**

* Os atacantes **invadiram a infraestrutura de CI/CD da SolarWinds**.
* Conseguiram **alterar o pipeline de build** para **injetar um trojan (SUNBURST)** dentro da DLL legítima.
* O software foi **assinado digitalmente** pela própria SolarWinds, passando por todas as verificações de integridade locais dos clientes.

---

**⚠️ Relação com OWASP A08 – Software and Data Integrity Failures**

Essa categoria cobre falhas em que:

> *“O código, a infraestrutura ou dados de uma aplicação podem ser comprometidos por falta de validação de integridade ou segurança na cadeia de fornecimento.”*

dA08 inclui riscos como:

* Deploy automático sem verificação.
* Ausência de **assinatura ou validação de artefatos**.
* Confiança excessiva em **pacotes externos ou dependências**.
* Pipelines CI/CD **mal protegidos** (como no caso da SolarWinds).

---

**🛡️ O que podemos aprender com isso (boas práticas)**

CI/CD seguro:

* **Use controles de acesso rigorosos** (RBAC) nos pipelines.
* **Registre e monitore** alterações em scripts de build e variáveis.
* **Use revisão de código obrigatória** para alterações em arquivos de pipeline (YAML, bash, Dockerfile).
* **Assine digitalmente os artefatos** e valide os hashes antes do deploy.

Verificações:

* Verifique a **integridade de dependências** (`composer audit`, `npm audit`, etc).
* Use ferramentas como:

  * [SLSA (Supply chain Levels for Software Artifacts)](https://slsa.dev/)
  * [Sigstore / Cosign](https://sigstore.dev/)
  * [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)

---

🧠 Conclusão

O ataque à SolarWinds mostrou que mesmo empresas com software confiável podem ser vetor de ataque quando há falhas de integridade no processo de build. Ele é um **exemplo real e devastador** do que o OWASP classifica como A08.

Quer que eu te mostre como aplicar algum desses controles (ex: auditoria de dependências ou validação de hash) no seu pipeline Azure DevOps para Laravel?


## Análise do Perplexity

<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" class="logo" width="120"/>

# A08:2021 - Falhas de Integridade de Software e Dados: Uma Análise Aprofundada

Esta análise explora a categoria A08:2021 do OWASP Top 10, focada nas falhas de integridade de software e dados. Trata-se de uma vulnerabilidade crítica introduzida na lista de 2021 que aborda riscos relacionados a atualizações de software, dados críticos e pipelines de CI/CD que não verificam adequadamente a integridade. Os impactos dessas falhas podem ser devastadores, resultando em comprometimento de sistemas, execução de código malicioso e perda de confiança nos aplicativos afetados.

## Contexto e Definição

As falhas de integridade de software e dados representam uma nova categoria no OWASP Top 10 de 2021, focando em vulnerabilidades que surgem quando componentes de software não verificados ou não confiáveis são introduzidos em sistemas. Esta categoria se concentra especificamente em suposições relacionadas a atualizações de software, dados críticos e pipelines de CI/CD sem a devida verificação de integridade[^1][^2].

De acordo com dados do OWASP, esta categoria está associada a 10 CWEs (Common Weakness Enumerations), apresenta uma taxa máxima de incidência de 16,67% e uma taxa média de incidência de 2,05%. O impacto médio ponderado é significativo em 7,94, tornando-a uma das categorias com maior impacto ponderado nos dados de CVE/CVSS[^1][^5].

As falhas de integridade de software e dados referem-se a código e infraestrutura que não protegem contra violações de integridade. Estas ocorrem quando sistemas dependem de plugins, bibliotecas ou módulos de fontes não confiáveis, ou quando atualizações de software são baixadas sem verificação de integridade suficiente e aplicadas ao aplicativo anteriormente confiável[^1][^5].

### Principais Vulnerabilidades Associadas

Entre as vulnerabilidades mais notáveis associadas a esta categoria estão:

- **CWE-829**: Inclusão de Funcionalidade de Esfera de Controle Não Confiável
- **CWE-494**: Download de Código Sem Verificação de Integridade
- **CWE-502**: Desserialização de Dados Não Confiáveis[^1][^5]

Estas fragilidades permitem que atacantes manipulem software ou dados, potencialmente levando ao controle não autorizado, violações de dados ou atividades maliciosas dentro dos aplicativos[^4].

## Causas e Mecanismos de Ataque

### Fontes das Vulnerabilidades

As falhas de integridade de software e dados geralmente resultam de várias práticas inseguras:

1. **Dependências não verificadas**: Aplicações que dependem de plugins, bibliotecas ou módulos de fontes não confiáveis, repositórios ou redes de distribuição de conteúdo (CDNs)[^1][^5].
2. **Pipelines de CI/CD inseguros**: Infraestruturas de integração e entrega contínuas com falhas de segurança podem introduzir potencial para acesso não autorizado, código malicioso ou comprometimento do sistema[^1].
3. **Funcionalidade de atualização automática insegura**: Aplicações que baixam atualizações sem verificação de integridade suficiente, permitindo que atacantes potencialmente distribuam suas próprias atualizações maliciosas[^1][^5].
4. **Desserialização insegura**: Quando objetos ou dados são codificados ou serializados em uma estrutura que um atacante pode ver e modificar, tornando-os vulneráveis à desserialização insegura[^1][^5].

### Ataques à Cadeia de Suprimentos de Software

Os ataques à cadeia de suprimentos de software tornaram-se particularmente alarmantes no contexto atual. Estes ocorrem quando atores maliciosos se infiltram em ecossistemas de software confiáveis, comprometendo dependências ou canais de distribuição[^4][^6].

## Cenários de Ataque e Casos Reais

### Cenário 1: Atualizações sem Assinatura

Muitos roteadores domésticos, decodificadores, firmware de dispositivos e outros não verificam atualizações por meio de firmware assinado. Firmware não assinado é um alvo crescente para atacantes, representando uma preocupação maior quando não há mecanismo para remediar além de corrigir em uma versão futura[^1][^5].

### Cenário 2: Ataque SolarWinds

O ataque SolarWinds Orion é um exemplo notável de comprometimento de mecanismos de atualização. Mesmo com processos seguros de construção e integridade de atualização, a empresa teve estes subvertidos. Durante vários meses, a empresa distribuiu uma atualização maliciosa altamente direcionada para mais de 18.000 organizações, das quais cerca de 100 foram afetadas. Este é considerado um dos ataques mais abrangentes e significativos deste tipo na história[^1][^5].

### Cenário 3: Desserialização Insegura

Um aplicativo React que chama um conjunto de microserviços Spring Boot pode enfrentar vulnerabilidades quando os desenvolvedores tentam garantir que seu código seja imutável serializando o estado do usuário e passando-o de um lado para outro com cada solicitação. Um atacante que percebe a assinatura do objeto Java "rO0" (em base64) pode usar ferramentas como Java Serial Killer para obter execução remota de código no servidor da aplicação[^1][^5].

## Impactos e Consequências

As falhas de integridade de software e dados podem ter consequências graves e de longo alcance:

### Comprometimento da Integridade dos Dados

Atacantes podem alterar, manipular ou corromper dados críticos, resultando em informações imprecisas sendo armazenadas ou processadas. Isso compromete a confiabilidade do sistema, especialmente em setores onde a integridade dos dados é vital, como finanças, saúde e direito[^3].

### Execução de Código Malicioso

A exploração de vulnerabilidades de software pode permitir que atacantes injetem código malicioso, levando à execução de comandos não autorizados. Isso pode causar comportamento imprevisível do sistema ou abrir backdoors para ataques adicionais[^3].

### Danos à Reputação

Violações de dados ou integridade frequentemente corroem a confiança entre usuários, clientes e parceiros, prejudicando a reputação da organização. Isso pode levar à perda de lealdade do cliente e, em última análise, a oportunidades de negócios perdidas[^3].

### Consequências Financeiras

Ataques à integridade de software e dados podem resultar em perdas financeiras significativas, incluindo multas por não conformidade e custos de recuperação[^3].

## Métodos de Prevenção e Mitigação

### Verificação de Integridade

Use assinaturas digitais ou mecanismos similares para verificar se o software ou dados são da fonte esperada e não foram alterados[^1][^5].

### Gestão de Dependências Seguras

Garanta que bibliotecas e dependências, como npm ou Maven, estejam consumindo repositórios confiáveis. Se você tiver um perfil de risco mais alto, considere hospedar um repositório interno conhecido como confiável e verificado[^1][^5].

### Ferramentas de Segurança da Cadeia de Suprimentos

Utilize ferramentas de segurança da cadeia de suprimentos de software, como OWASP Dependency Check ou OWASP CycloneDX, para verificar se os componentes não contêm vulnerabilidades conhecidas[^5].

### Processos de Revisão de Código

Implemente um processo de revisão para alterações de código e configuração para minimizar a chance de código malicioso ou configuração serem introduzidos em seu pipeline de software[^5].

### Segregação e Controle de Acesso no CI/CD

Garanta que seu pipeline de CI/CD tenha segregação adequada, configuração e controle de acesso para garantir a integridade do código fluindo através dos processos de construção e implantação[^5].

### Proteção contra Desserialização Insegura

Certifique-se de que dados serializados não assinados ou não criptografados não sejam enviados para clientes não confiáveis sem alguma forma de verificação de integridade ou assinatura digital para detectar adulteração ou reprodução dos dados serializados[^5].

## Melhores Práticas de Segurança

### Princípios de Segurança Básicos

Adira aos princípios básicos de segurança de privilégios mínimos e separação de deveres, impondo autenticação multifator (MFA), rotação de credenciais e garantindo repositórios confiáveis para suas dependências[^6].

### Segurança no Desenvolvimento

Integre práticas de segurança em todo o ciclo de vida de desenvolvimento de software, incluindo:

1. Análise estática de código fonte
2. Verificações de composição de software
3. Testes de segurança automatizados
4. Revisões de código com foco em segurança[^6]

### Segurança nos Ambientes de Desenvolvimento

Proteja seus ambientes de desenvolvimento, sistemas de controle de versão e pipelines de CI/CD contra acesso não autorizado ou manipulação. Use ferramentas específicas para monitorar e verificar a integridade do código em todas as etapas[^6].

## Conclusão

As falhas de integridade de software e dados representam uma ameaça substancial e crescente no cenário atual de segurança cibernética. Com a crescente dependência de componentes de terceiros, atualizações automáticas e pipelines de CI/CD, a superfície de ataque para estas vulnerabilidades continua a se expandir.

A mitigação eficaz dessas falhas requer uma abordagem multifacetada, incluindo verificações rigorosas de integridade, gestão segura de dependências e processos robustos de revisão de código. Organizações devem adotar uma mentalidade de "confiança zero" em relação à integridade do software, verificando cada componente e atualização antes da integração.

À medida que ataques como o SolarWinds demonstram, até mesmo organizações com processos de segurança aparentemente sólidos podem ser comprometidas através da cadeia de suprimentos de software. Portanto, a vigilância contínua, a educação dos desenvolvedores e a implementação de controles de segurança em camadas são essenciais para proteger contra estas sofisticadas ameaças à integridade de software e dados.

<div style="text-align: center">⁂</div>

[^1]: https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/

[^2]: https://owasp.org/Top10/

[^3]: https://community.f5.com/kb/technicalarticles/mitigating-owasp-web-app-risks-software-and-data-integrity-failures-using-big-ip/340228

[^4]: https://krishnag.ceo/blog/software-and-data-integrity-failures-a-critical-concern-for-developers/

[^5]: https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/

[^6]: https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html

[^7]: https://www.cvedetails.com/cwe-details/494/Download-of-Code-Without-Integrity-Check.html

[^8]: https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data

[^9]: https://cwe.mitre.org/data/definitions/829.html

[^10]: https://cwe.mitre.org/data/definitions/830.html

[^11]: https://www.cvedetails.com/cwe-details/915/Improperly-Controlled-Modification-of-Dynamically-Determined.html

[^12]: https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident

[^13]: https://en.wikipedia.org/wiki/WannaCry_ransomware_attack

[^14]: https://www.cfcs.dk/globalassets/cfcs/dokumenter/rapporter/en/CFCS-solarwinds-report-EN.pdf

[^15]: https://owasp.org/Top10/pt_BR/A08_2021-Software_and_Data_Integrity_Failures/

[^16]: https://cheatsheetseries.owasp.org/index.html

[^17]: https://www.securityjourney.com/post/owasp-top-10-software-and-integrity-failures-explained

[^18]: https://www.reversinglabs.com/blog/owasp-supply-chain-security-cheat-sheet

[^19]: https://www.invicti.com/blog/web-security/software-and-data-integrity-failures-an-owasp-top-10-risk/

[^20]: https://www.linkedin.com/pulse/understanding-a082021-software-data-integrity-failures-ftlgc

[^21]: https://owasp.org/www-project-top-ten/

[^22]: https://www.perallis.com.br/blog/the-owasp-top-10-2021-what-has-changed-in-the-new-version-of-the-ranking

[^23]: https://www.ionix.io/guides/owasp-top-10/software-and-data-integrity-failures/

[^24]: https://qawerk.com/blog/software-and-data-integrity-failures/

[^25]: https://wiki.genexus.com/commwiki/wiki?50188%2CA08%3A2021+-+Software+and+data+integrity+failures

[^26]: https://cecyber.com/owasp-top-10-web-application-security-risks-2021/

[^27]: https://protean-labs.io/blog/security-breach-spotlight:-owasp-top-8-software-and-data-integrity-failures

[^28]: https://www.wallarm.com/what/a04-2021-owasp-software-and-data-integrity-failures

[^29]: https://www.xlabs.com.br/blog/saiba-quais-sao-as-vulnerabilidades-do-top-10-da-owasp-2021/

[^30]: https://blog.grancursosonline.com.br/owasp-top-10-de-2021-parte-04/

[^31]: https://www.youtube.com/watch?v=NJjjQxHWe3I

[^32]: https://my.f5.com/manage/s/article/K000147753

[^33]: https://owasp.org/www-project-cheat-sheets/

[^34]: https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/CI_CD_Security_Cheat_Sheet.md

[^35]: https://appsec.backslash.security/cwe/494

[^36]: https://www.cvedetails.com/cwe-details/502/Deserialization-of-Untrusted-Data.html

[^37]: https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html

[^38]: https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html

[^39]: https://www.cvedetails.com/cve/CVE-2025-1058/

[^40]: https://support.waratek.com/knowledge/best-practices-unsafe-deserialization-of-untrusted-data

[^41]: https://www.kusari.dev/resource-library/owasp-supply-chain-security-cheat-sheet-5-key-action-items

[^42]: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

[^43]: https://cwe.mitre.org/data/definitions/494.html

[^44]: https://cyberpolygon.com/materials/insecure-deserialisation/

[^45]: https://docs.gitlab.com/ee/user/application_security/dast/browser/checks/829.1.html

[^46]: https://codeql.github.com/codeql-query-help/javascript/js-functionality-from-untrusted-source/

[^47]: https://www.cvedetails.com/cwe-details/345/Insufficient-Verification-of-Data-Authenticity.html

[^48]: https://cwe.mitre.org/data/definitions/353.html

[^49]: https://cxsecurity.com/cwe/CWE-829/

[^50]: https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/

[^51]: https://cwe.mitre.org/data/definitions/345.html

[^52]: https://appsec.backslash.security/cwe/353

[^53]: https://opencre.org/node/standard/CWE/section/Inclusion of Functionality from Untrusted Control Sphere

[^54]: https://cwe.mitre.org/data/definitions/1354.html

[^55]: https://www.ibm.com/support/pages/security-bulletin-insufficient-verification-data-authenticity-might-affect-ibm-storage-defender-–-resiliency-service

[^56]: https://www.martellosecurity.com/kb/mitre/cwe/353/

[^57]: https://www.cvedetails.com/cwe-details/784/Reliance-on-Cookies-without-Validation-and-Integrity-Checkin.html

[^58]: https://www.cvedetails.com/cwe-details/915/Improperly-Controlled-Modification-of-Dynamically-Determined.html

[^59]: https://www.cybersecurity-help.cz/vdb/cwe/565/

[^60]: https://cwe.mitre.org/data/definitions/784.html

[^61]: https://cwe.mitre.org/data/definitions/915.html

[^62]: https://nvd.nist.gov/vuln/detail/CVE-2023-32725

[^63]: https://cwe.mitre.org/data/published/cwe_v2.11.pdf

[^64]: https://appsec.backslash.security/cwe/915

[^65]: https://hackerone.com/hacktivity/cwe_discovery?id=CWE-565

[^66]: https://docs.hackerone.com/en/articles/8475337-types-of-weaknesses

[^67]: https://www.veracode.com/security/dotnet/cwe-915/

[^68]: https://portswigger.net/kb/issues/00500b02_cookie-manipulation-stored-dom-based

[^69]: https://www.martellosecurity.com/kb/mitre/cwe/784/

[^70]: https://support.codesecure.com/hc/en-us/articles/4575742226705-MITRE-s-CWE-Common-Weakness-Enumeration

[^71]: https://webtechsurvey.com/cwe/CWE-915

[^72]: https://cwe.mitre.org/data/definitions/913.html

[^73]: https://jvndb.jvn.jp/ja/cwe/CWE-784.html

[^74]: https://cwe.mitre.org/data/definitions/1321.html

[^75]: https://www.martellosecurity.com/kb/mitre/cwe/915/

[^76]: https://www.opencre.org/node/standard/CWE/sectionid/915

[^77]: https://www.clouddefense.ai/cwe/definitions/915

[^78]: https://cwe.mitre.org/data/definitions/1415.html

[^79]: https://www.cloudflare.com/learning/security/ransomware/wannacry-ransomware/

[^80]: https://www.techtarget.com/whatis/feature/SolarWinds-hack-explained-Everything-you-need-to-know

[^81]: https://dl.acm.org/doi/10.1145/3517208.3523753

[^82]: https://www.fortinet.com/br/resources/cyberglossary/wannacry-ransomeware-attack

[^83]: https://cloud.google.com/blog/products/identity-security/how-solarwinds-still-affects-supply-chain-threats-two-years-later

[^84]: https://www.sonatype.com/blog/open-source-software-is-under-attack-new-event-stream-hack-is-latest-proof

[^85]: https://www.kaspersky.com/resource-center/threats/ransomware-wannacry

[^86]: https://www.fortinet.com/resources/cyberglossary/solarwinds-cyber-attack

[^87]: https://www.cisa.gov/news-events/alerts/2017/05/12/indicators-associated-wannacry-ransomware

[^88]: https://www.solarwinds.com/blog/future-software-supply-chain-security

[^89]: https://www.kaspersky.com.br/resource-center/threats/ransomware-wannacry

[^90]: https://www.techtarget.com/searchsecurity/ehandbook/SolarWinds-supply-chain-attack-explained-Need-to-know-info

[^91]: https://www.oligo.security/academy/owasp-top-10-cheat-sheet-of-cheat-sheets

[^92]: https://myrror.security/owasp-cheat-sheet-for-sldc-with-downloadable-xls-myrror/

[^93]: https://dev.to/yayabobi/owasp-cheat-sheet-for-sdlc-with-downloadable-xls-4pjm

[^94]: https://community.veracode.com/s/article/How-to-fix-CWE-829-issues-in-Veracode

[^95]: https://cvefeed.io/cwe/detail/cwe-829-inclusion-of-functionality-from-untrusted-control-sphere

[^96]: https://stackoverflow.com/questions/57162032/how-to-fix-cwe-829-inclusion-of-functionality-from-untrusted-control-sphere

[^97]: https://vulnerabilityhistory.org/tags/cwe-829

[^98]: https://www.security-database.com/cwe.php?name=CWE-345

[^99]: https://docs.sec1.io/user-docs/4-sast/2-java/missing-support-for-integrity-check

[^100]: https://www.cvedetails.com/cwe-details/565/Reliance-on-Cookies-without-Validation-and-Integrity-Checkin.html

[^101]: https://cwe.mitre.org/data/definitions/565.html

[^102]: https://www.clouddefense.ai/cwe/definitions/565

[^103]: https://appsec.backslash.security/cwe/565

[^104]: https://www.cvedetails.com/cwe-definitions/10/cwelist.html?order=2\&trc=668\&sha=0427874cc45423ccb6974ee25935fbfceac76fcb

[^105]: https://www.cvedetails.com/cwe-definitions/7/cwelist.html?order=2\&trc=668\&sha=0427874cc45423ccb6974ee25935fbfceac76fcb

[^106]: https://www.cvedetails.com/cwe-definitions/6/cwelist.html?order=3\&trc=668\&sha=0427874cc45423ccb6974ee25935fbfceac76fcb

[^107]: https://cvefeed.io/cwe/detail/cwe-565-reliance-on-cookies-without-validation-and-integrity-checking

[^108]: https://www.clouddefense.ai/cwe/definitions/784

[^109]: https://www.cvedetails.com/cwe-definitions/13/cwelist.html?order=1\&trc=938\&sha=29ad19bb04476ff1cba0d39cdfb5d273032a8ed4

[^110]: https://chenweixiang.github.io/docs/CWE_List_v3.1.pdf

[^111]: https://cloud.google.com/blog/topics/threat-intelligence/supply-chain-node-js

[^112]: https://www.revenera.com/blog/software-composition-analysis/compromised-npm-package-event-stream-and-flatmap-stream-packages-lead-to-supply-chain-attack/

[^113]: https://www.techtarget.com/searchsecurity/news/252453398/Compromised-NPM-package-highlights-open-source-trouble

[^114]: https://soundcloud.com/owasp-podcast/event-stream-analysis-of-a-compromised-npm-package

[^115]: https://gist.github.com/dominictarr/9fd9c1024c94592bc7268d36b8d83b3a

