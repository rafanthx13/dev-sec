# App Sec Tools For PHP

## ChatGPT

> Existe alguma ferramenta de analise estatiaca appsec para php?

Sim, Rafael, existem várias ferramentas de **análise estática de segurança (SAST)** voltadas para **PHP**, que ajudam a identificar falhas de segurança no código **sem executá-lo**. Aqui estão as mais conhecidas e eficazes:

---

## 🛠️ **Ferramentas SAST para PHP / AppSec**

| Ferramenta            | Descrição                                                                | Tipo de Falhas Detectadas                                                      |
| --------------------- | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------ |
| **Psalm**             | Ferramenta de análise estática avançada para PHP, com suporte a plugins  | XSS, SQLi, variáveis não inicializadas, tipos, vulnerabilidades personalizadas |
| **PHPStan**           | Analisa código PHP em busca de erros de lógica e segurança               | SQLi, XSS, erros de tipo e boas práticas                                       |
| **SonarQube**         | Plataforma robusta com suporte a várias linguagens, incluindo PHP        | XSS, SQLi, CSRF, falhas de autenticação, código duplicado                      |
| **Exakat**            | Ferramenta específica para segurança e qualidade em PHP                  | Vulnerabilidades OWASP, más práticas, código legado                            |
| **RIPS (deprecated)** | Ferramenta SAST famosa focada em segurança PHP (agora parte do Sonar)    | Análise profunda de fluxo de dados para detectar vulnerabilidades              |
| **PHP\_CodeSniffer**  | Foca em estilo de código, mas pode ser combinado com regras de segurança | Código inseguro por convenções (usado junto de outras tools)                   |
| **Progpilot**         | Ferramenta específica para análise de segurança estática em PHP          | SQLi, XSS, LFI, RCE, comandos perigosos                                        |

---

## 📌 Exemplos de uso

### Psalm:

```bash
composer require --dev vimeo/psalm
vendor/bin/psalm
```

### PHPStan:

```bash
composer require --dev phpstan/phpstan
vendor/bin/phpstan analyse src/
```

### SonarQube:

* Requer servidor.
* Análise via [SonarScanner CLI](https://docs.sonarsource.com/sonarqube/latest/analyzing-source-code/scanners/sonarscanner/).

### Exakat:

```bash
docker run --rm -v $(pwd):/app exakat/exakat exakat.phar -p myproject -v
```

---

## ✅ Recomendações para projetos Laravel

* **Psalm + plugin de Laravel**: [psalm/plugin-laravel](https://github.com/psalm/laravel-plugin).
* **PHPStan com nível alto + larastan**: [nunomaduro/larastan](https://github.com/nunomaduro/larastan).

---

Se quiser, posso te ajudar a configurar uma dessas ferramentas no seu projeto Laravel ou PHP puro. Deseja isso?
