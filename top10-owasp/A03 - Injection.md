# A03 - Injection

## Resumo

SQL Injection. É sempre pensar que o usuario pode passar algo errado, esquisito pro servidor e este executar elago, entao, sempre é bom validar e sanetizar

## Links

+ https://owasp.org/Top10/pt_BR/A03_2021-Injection/

## Owasp

## Visão Geral

A Injeção desliza para a terceira posição. 94% das aplicações foram testadas para alguma forma de injeção com uma taxa de incidência máxima de 19%, uma taxa de incidência média de 3% e 274k ocorrências. Notável  _Common Weakness Enumerations_  (CWEs) incluídas são  _CWE-79: Cross-site Scripting_,  _CWE-89: Injeção de SQL_  e  _CWE-73: Controle Externo do Nome do Arquivo ou Caminho_.

## Descrição

Uma aplicação é vulnerável a ataques quando:

+ Os dados fornecidos pelo usuário não são validados, filtrados ou higienizados pelo aplicativo.

+ Consultas dinâmicas ou chamadas não parametrizadas sem escape ciente do contexto são usadas diretamente no interpretador.

+ Dados hostis são usados nos parâmetros de pesquisa de mapeamento relacional de objeto (ORM) para extrair registros confidenciais adicionais.

+ Os dados fornecidos pelo usuário não são validados, filtrados ou higienizados pelo aplicativo.

+ Consultas dinâmicas ou chamadas não parametrizadas sem escape ciente do contexto são usadas diretamente no interpretador.

+ Dados hostis são usados nos parâmetros de pesquisa de mapeamento relacional de objeto (ORM) para extrair registros confidenciais adicionais.

+ Dados hostis são usados diretamente ou concatenados. O SQL ou comando contém a estrutura e os dados maliciosos em consultas dinâmicas, comandos ou procedimentos armazenados.

Algumas das injeções mais comuns são SQL, NoSQL, comando OS, Mapeamento Relacional de Objeto (ORM), LDAP e Linguagem de Expressão (EL) ou injeção de Biblioteca de Navegação de Gráfico de Objeto (OGNL). O conceito é idêntico entre todos os intérpretes. A revisão do código-fonte é o melhor método para detectar se os aplicativos são vulneráveis a injeções. O teste automatizado de todos os parâmetros, cabeçalhos, URL, cookies, JSON, SOAP e entradas de dados XML são fortemente encorajados. As organizações podem incluir ferramentas de teste de segurança de aplicações estáticos (SAST), dinâmicos (DAST) e interativos (IAST) no pipeline de CI/CD para identificar as falhas de injeção introduzidas antes da implantação da produção.

## Como Prevenir

Prevenir a injeção requer manter os dados separados dos comandos e consultas:

+ A opção preferida é usar uma API segura, que evita usar o interpretador inteiramente, fornece uma interface parametrizada ou migra para uma ferramenta de Mapeamento Relacional de Objeto (ORMs).  
    **Nota:**  Mesmo quando parametrizados, os procedimentos armazenados ainda podem introduzir injeção de SQL se PL/SQL ou T-SQL concatenar consultas e dados ou executar dados hostis com EXECUTE IMMEDIATE ou exec().

+ Use validação de entrada positiva ou "_safelist_" do lado do servidor. Esta não é uma defesa completa, pois muitos aplicativos requerem caracteres especiais, como áreas de texto ou APIs para aplicativos móveis.

+ Para quaisquer consultas dinâmicas residuais, escape os caracteres especiais usando a sintaxe de escape específica para esse interpretador..  
    **Nota:**  Estruturas SQL, como nomes de tabelas, nomes de colunas e assim por diante, não podem ter escape e, portanto, nomes de estruturas fornecidos pelo usuário são perigosos. Este é um problema comum em software de elaboração de relatórios.

+ Use LIMIT e outros SQL de controle em consultas para evitar a divulgação em massa de registros no caso de injeção de SQL.

## Exemplos de Cenários de Ataque

**Cenário #1:**  Um aplicativo usa dados não confiáveis na construção da seguinte chamada SQL vulnerável:

```
String query = "SELECT \* FROM accounts WHERE custID='" + request.getParameter("id") + "'";

```

**Cenário #2:**  Da mesma forma, a confiança cega em  _frameworks_  de aplicaçãos pode resultar em consultas que ainda são vulneráveis (por exemplo, Hibernate Query Language (HQL)):

```
 Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");

```

Em ambos os casos, o invasor modifica o valor do parâmetro ‘_id_’ em seu navegador para enviar:  _‘ or ‘1’=’1_. Por exemplo:

```
 http://example.com/app/accountView?id=' UNION SELECT SLEEP(10);--

```

Isso muda o significado de ambas as consultas para retornar todos os registros da tabela de contas. Ataques mais perigosos podem modificar ou excluir dados ou até mesmo invocar procedimentos armazenados.

## Referências

+ [OWASP Proactive Controls: Secure Database Access](https://owasp.org/www-project-proactive-controls/v3/en/c3-secure-database)

+ [OWASP ASVS: V5 Input Validation and Encoding](https://owasp.org/www-project-application-security-verification-standard)

+ [OWASP Testing Guide: SQL Injection,](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) [Command Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection)  e [ORM Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection)

+ [OWASP Cheat Sheet: Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)

+ [OWASP Cheat Sheet: SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

+ [OWASP Cheat Sheet: Injection Prevention in Java](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html)

+ [OWASP Cheat Sheet: Query Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)

+ [OWASP Automated Threats to Web Applications – OAT-014](https://owasp.org/www-project-automated-threats-to-web-applications/)

+ [PortSwigger: Server-side template injection](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)

## Lista dos CWEs Mapeados

[CWE-20 Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

[CWE-74 Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)

[CWE-75 Failure to Sanitize Special Elements into a Different Plane (Special Element Injection)](https://cwe.mitre.org/data/definitions/75.html)

[CWE-77 Improper Neutralization of Special Elements used in a Command ('Command Injection')](https://cwe.mitre.org/data/definitions/77.html)

[CWE-78 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)

[CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)

[CWE-80 Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)](https://cwe.mitre.org/data/definitions/80.html)

[CWE-83 Improper Neutralization of Script in Attributes in a Web Page](https://cwe.mitre.org/data/definitions/83.html)

[CWE-87 Improper Neutralization of Alternate XSS Syntax](https://cwe.mitre.org/data/definitions/87.html)

[CWE-88 Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')](https://cwe.mitre.org/data/definitions/88.html)

[CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)

[CWE-90 Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')](https://cwe.mitre.org/data/definitions/90.html)

[CWE-91 XML Injection (aka Blind XPath Injection)](https://cwe.mitre.org/data/definitions/91.html)

[CWE-93 Improper Neutralization of CRLF Sequences ('CRLF Injection')](https://cwe.mitre.org/data/definitions/93.html)

[CWE-94 Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)

[CWE-95 Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html)

[CWE-96 Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')](https://cwe.mitre.org/data/definitions/96.html)

[CWE-97 Improper Neutralization of Server-Side Includes (SSI) Within a Web Page](https://cwe.mitre.org/data/definitions/97.html)

[CWE-98 Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')](https://cwe.mitre.org/data/definitions/98.html)

[CWE-99 Improper Control of Resource Identifiers ('Resource Injection')](https://cwe.mitre.org/data/definitions/99.html)

[CWE-100 Deprecated: Was catch-all for input validation issues](https://cwe.mitre.org/data/definitions/100.html)

[CWE-113 Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')](https://cwe.mitre.org/data/definitions/113.html)

[CWE-116 Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)

[CWE-138 Improper Neutralization of Special Elements](https://cwe.mitre.org/data/definitions/138.html)

[CWE-184 Incomplete List of Disallowed Inputs](https://cwe.mitre.org/data/definitions/184.html)

[CWE-470 Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')](https://cwe.mitre.org/data/definitions/470.html)

[CWE-471 Modification of Assumed-Immutable Data (MAID)](https://cwe.mitre.org/data/definitions/471.html)

[CWE-564 SQL Injection: Hibernate](https://cwe.mitre.org/data/definitions/564.html)

[CWE-610 Externally Controlled Reference to a Resource in Another Sphere](https://cwe.mitre.org/data/definitions/610.html)

[CWE-643 Improper Neutralization of Data within XPath Expressions ('XPath Injection')](https://cwe.mitre.org/data/definitions/643.html)

[CWE-644 Improper Neutralization of HTTP Headers for Scripting Syntax](https://cwe.mitre.org/data/definitions/644.html)

[CWE-652 Improper Neutralization of Data within XQuery Expressions ('XQuery Injection')](https://cwe.mitre.org/data/definitions/652.html)

[CWE-917 Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')](https://cwe.mitre.org/data/definitions/917.html)

## ChatGPT

### Q3

> Fale sobre A03 Injection

Ótimo pedido! A seguir, listo exemplos **reais e perigosos** de **vulnerabilidades de injeção em PHP**, **além de SQL Injection**, incluindo injeções de comandos do sistema, headers HTTP, arquivos e outros vetores frequentemente explorados.

---

### 1. 🧨 **Command Injection** (Injeção de comandos do sistema)

**Vulnerável:**

```php
$arquivo = $_GET['arquivo'];
system("ls " . $arquivo);
```

**Exploração:**

```
?arquivo=; cat /etc/passwd
```

**O que acontece?**

```bash
ls ; cat /etc/passwd
```

➡ Lista arquivos e depois imprime o conteúdo sensível de `/etc/passwd`.

**Proteção:**

+ Nunca concatene parâmetros diretamente com comandos.
+ Use `escapeshellarg()`:

```php
$arquivo = escapeshellarg($_GET['arquivo']);
system("ls $arquivo");
```

---

### 2. 📩 **Email Header Injection**

**Vulnerável:**

```php
$to = $_POST['email'];
mail($to, "Assunto", "Mensagem", "From: admin@site.com");
```

**Exploração:**

```
email=vítima@example.com%0ABcc: atacante@example.com
```

➡ O atacante insere novos cabeçalhos no email.

**Proteção:**

+ Valide e filtre entradas com `filter_var($email, FILTER_VALIDATE_EMAIL)`.

---

### 3. 📄 **Local File Inclusion (LFI)**

**Vulnerável:**

```php
$page = $_GET['page'];
include("paginas/$page.php");
```

**Exploração:**

```
?page=../../../../etc/passwd
```

➡ Pode permitir leitura de arquivos arbitrários ou execução de código se combinado com upload.

**Proteção:**

+ Nunca use entrada do usuário diretamente em `include()`, `require()`, etc.
+ Use uma lista de páginas permitidas:

```php
$whitelist = ['inicio', 'contato', 'sobre'];
if (in_array($page, $whitelist)) {
    include("paginas/$page.php");
}
```

---

### 4. 🗂️ **Object Injection (Deserialização insegura)**

**Vulnerável:**

```php
$data = $_GET['data'];
$obj = unserialize($data);
```

**Exploração:**
Um atacante pode enviar um objeto malicioso com métodos `__destruct` ou `__wakeup` que executam código.

**Proteção:**

+ Evite `unserialize()` em dados não confiáveis.
+ Use `json_decode()` se possível, ou use `allowed_classes` no `unserialize()`:

```php
unserialize($data, ['allowed_classes' => false]);
```

---

### 5. 🌐 **Cross-site Scripting (XSS)**

**Vulnerável:**

```php
$nome = $_GET['nome'];
echo "Olá, $nome!";
```

**Exploração:**

```
?nome=<script>alert('XSS')</script>
```

➡ Código JavaScript malicioso é executado no navegador da vítima.

**Proteção:**

+ Escape a saída com `htmlspecialchars()`:

```php
echo "Olá, " . htmlspecialchars($nome, ENT_QUOTES, 'UTF-8');
```

---

Esses exemplos mostram como **diversos tipos de injeção** podem surgir no PHP quando dados do usuário não são tratados corretamente.
Quer que eu revise um trecho seu para te ajudar a identificar falhas potenciais?

### Q4

> No php tem como por meio de injection executar comandos?

Sim, **no PHP é possível executar comandos do sistema operacional via injection**, o que é chamado de **Command Injection** (ou "injection de comandos shell"). Isso ocorre quando entradas do usuário são **inseridas diretamente** em funções que executam comandos no sistema, como:

+ `system()`
+ `exec()`
+ `shell_exec()`
+ `passthru()`
+ `popen()`

---

### 🧨 Exemplo prático de Command Injection

```php
<?php
$arquivo = $_GET['arquivo']; // Ex: input do usuário
system("ls $arquivo");
?>
```

**Exploração:**

```
http://exemplo.com/script.php?arquivo=;cat+/etc/passwd
```

O comando executado será:

```bash
ls ; cat /etc/passwd
```

➡ Isso lista os arquivos e depois imprime o conteúdo de `/etc/passwd`, um arquivo sensível.

---

### 🛡️ Como se proteger

**1. Nunca confie diretamente em entradas do usuário.**

**2. Escape corretamente:**

```php
$arquivo = escapeshellarg($_GET['arquivo']);
system("ls $arquivo");
```

**3. Use listas brancas (whitelists):**

```php
$permitidos = ['documentos', 'imagens'];
if (in_array($_GET['arquivo'], $permitidos)) {
    system("ls " . escapeshellarg($_GET['arquivo']));
}
```

---

### ✅ Alternativas seguras

+ Prefira usar funções nativas do PHP para manipulação de arquivos/diretórios em vez de comandos shell:

    + `scandir()`
    + `file_get_contents()`
    + `unlink()`
    + `copy()`
    + etc.

---

### 🚨 Observação crítica

Command Injection pode permitir que o atacante:

+ Leia e apague arquivos
+ Crie backdoors
+ Baixe malware
+ Suba shells reversas e assuma o servidor

Em ambientes mal configurados, um único `system($_GET['cmd'])` pode comprometer todo o sistema.

---

Se quiser, posso criar um script vulnerável e uma versão segura para comparar. Deseja isso?

---=======================
---=======================
---=======================
---=======================
---=======================
---=======================

## Perplexity

<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" class="logo" width="120"/>

# A03: Injeção - Vulnerabilidades e Exemplos em PHP Além de SQL Injection

A categoria **A03: Injeção** no OWASP Top 10 2021 engloba vulnerabilidades que permitem a execução de comandos não autorizados em sistemas através da manipulação de entradas não validadas. Embora a **SQL Injection** seja a mais conhecida, outras formas de injeção são igualmente críticas, especialmente em aplicações PHP. Este relatório explora exemplos práticos de injeção em PHP além do SQL, analisando mecanismos de exploração, impactos e estratégias de mitigação.

---

## Tipos de Injeção em PHP

### 1. Injeção de Comando (Command Injection)

Ocorre quando entradas de usuário são passadas diretamente para funções que executam comandos no sistema operacional, como `system()`, `exec()`, ou `passthru()`. Um exemplo clássico é um formulário que permite pingar um endereço IP:

```php
<?php
$ip = $_GET['ip'];
system("ping -c 4 " . $ip);
?>
```

Se um atacante inserir `8.8.8.8; rm -rf /`, o sistema executará `ping -c 4 8.8.8.8` seguido de `rm -rf /`, resultando na exclusão de arquivos[^4].
**Prevenção**: Use `escapeshellarg()` ou `escapeshellcmd()` para sanitizar entradas:

```php
$ip = escapeshellarg($_GET['ip']);
system("ping -c 4 " . $ip);
```

---

### 2. Injeção LDAP

Aplicações que autenticam usuários via LDAP sem sanitização adequada são vulneráveis. Considere este trecho de código que constrói uma consulta LDAP dinamicamente:

```php
$username = $_POST['username'];
$filter = "(uid=" . $username . ")";
$ldap_conn = ldap_connect("ldap.example.com");
ldap_search($ldap_conn, "dc=example,dc=com", $filter);
```

Se um usuário inserir `*)(uid=*))(|(uid=*`, a consulta se tornará `(uid=*)(uid=*))(|(uid=*)`, retornando todos os registros[^5].
**Prevenção**: Use `ldap_escape()` para filtrar caracteres especiais:

```php
$username = ldap_escape($_POST['username'], "", LDAP_ESCAPE_FILTER);
```

---

### 3. Injeção XML (XXE - XML External Entity)

A análise de XML não segura permite a inclusão de entidades externas. Por exemplo:

```php
$xml = <<<XML
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>
XML;
$data = simplexml_load_string($xml);
echo $data;
```

Isso exporia o conteúdo de `/etc/passwd`[^3].
**Prevenção**: Desative entidades externas com:

```php
libxml_disable_entity_loader(true);
```

---

### 4. Injeção de Objetos PHP (PHP Object Injection)

Ocorre quando dados serializados são desserializados sem validação. Por exemplo:

```php
class User {
    public $role = "guest";
    function __destruct() {
        if ($this->role === "admin") {
            system($_GET['cmd']);
        }
    }
}
$user = unserialize($_COOKIE['user']);
```

Se um atacante definir `user` como `O:4:"User":1:{s:4:"role";s:5:"admin";}`, o destructor executará comandos arbitrários[^4].
**Prevenção**: Evite desserialização de fontes não confiáveis ou use formatos seguros como JSON.

---

## Estratégias de Mitigação

### Validação de Entrada

+ **Listas de permissão**: Restrinja entradas a padrões conhecidos (e.g., apenas números em campos de IP).
+ **Sanitização contextual**: Use funções como `htmlspecialchars()` para saída HTML ou `addslashes()` para bancos de dados[^3].

### Configuração Segura

+ Desative funções perigosas no `php.ini`:

```ini
disable_functions = exec, system, passthru, shell_exec
```

+ Configure o PHP para executar em modo restrito (`safe_mode` em versões antigas).

### Uso de APIs Seguras

+ Substitua funções inseguras por alternativas modernas:
    + **PDO** para consultas SQL parametrizadas.
    + **DOMDocument** com `LIBXML_NONET` para análise XML segura.

---

## Conclusão

A injeção em PHP vai além do SQL, abrangendo vetores como comandos do sistema, LDAP, XML e desserialização de objetos. A prevenção exige uma combinação de validação rigorosa, sanitização contextual e configurações seguras. Desenvolvedores devem adotar princípios como **menor privilégio** e **defesa em profundidade** para minimizar riscos. Ferramentas como **SAST (Static Application Security Testing)** e análises de código automatizadas são essenciais para identificar pontos fracos durante o desenvolvimento[^1][^3].

<div style="text-align: center">⁂</div>

[^1]: https://www.youtube.com/watch?v=mR2ubE0YJ5o

[^2]: https://outpost24.com/blog/owasp-top-10-2021-what-is-new/

[^3]: https://www.ituonline.com/comptia-securityx/comptia-securityx-4/injection-vulnerabilities-analyzing-vulnerabilities-and-attacks/

[^4]: https://medium.com/@bdemir/a-pentesters-guide-to-code-injection-dcfa774a4431

[^5]: https://gist.github.com/sergiopantoja/7678542

[^6]: https://help.fluidattacks.com/portal/en/kb/articles/criteria-fixes-php-106

[^7]: https://docs.fluidattacks.com/criteria/fixes/php/323/

[^8]: https://riptutorial.com/php/example/11883/cross-site-scripting--xss-

[^9]: https://github.com/amir-h-fallahi/xpath-injection

[^10]: https://knowledge-base.secureflag.com/vulnerabilities/sql_injection/sql_injection_php.html

[^11]: https://owasp.org/Top10/A03_2021-Injection/

[^12]: https://www.cobalt.io/blog/a-pentesters-guide-to-code-injection

[^13]: https://github.com/thiiagoms/php-xss-example

[^14]: https://www.youtube.com/watch?v=4PTXq8YUmDI

[^15]: https://dev.to/sainsec/command-injection-course-content-3o74

[^16]: https://www.youtube.com/watch?v=Quq3FYa7Svk

[^17]: https://www.stackhawk.com/blog/php-command-injection/

[^18]: https://www.gratitech.com/blog/overview-of-owasp-top-10-v2021-a03-injection

[^19]: https://www.youtube.com/watch?v=COW4PauQKsQ

[^20]: https://www.immuniweb.com/blog/OWASP-injection.html

[^21]: https://owasp.org/Top10/

[^22]: https://www.code-intelligence.com/blog/types-of-injection-vulnerabilities

[^23]: https://lab.wallarm.com/spotlight-on-injection/

[^24]: https://www.secura.com/blog/owasp-top-10-2021

[^25]: https://www.acunetix.com/blog/articles/injection-attacks/

[^26]: https://github.com/3ls3if/Cybersecurity-Notes/blob/main/readme/owasp-top-10/web/a03-2021-injection.md

[^27]: https://www.immuniweb.com/owasp-top-10/

[^28]: https://www.zscaler.com/blogs/product-insights/owasp-top-10-injection-attacks-explained

[^29]: https://owasp.org/Top10/id/A03_2021-Injection/

[^30]: https://www.linkedin.com/pulse/understanding-owasps-a032021-safeopssecurity-xcwxe

[^31]: https://cybersecuritynews.com/injection-attacks/

[^32]: https://www.linkedin.com/posts/safeopssecurity_understanding-owasps-a032021-activity-7265801216662585344-tN_b

[^33]: https://github.com/amir-h-fallahi/xpath-injection

[^34]: https://www.youtube.com/watch?v=eLegWAPMgFs

[^35]: https://swisskyrepo.github.io/PayloadsAllTheThings/LDAP Injection/

[^36]: https://www.rapid7.com/blog/post/2014/06/12/you-have-no-sql-inj-sorry-nosql-injections-in-your-application/

[^37]: https://help.fluidattacks.com/portal/en/kb/articles/criteria-fixes-php-323

[^38]: https://www.w3schools.com/php/func_simplexml_xpath.asp

[^39]: https://www.youtube.com/watch?v=MfAcSNwCeJI

[^40]: https://www.twingate.com/blog/glossary/ldap injection

[^41]: https://hacktricks.boitatech.com.br/pentesting-web/nosql-injection

[^42]: https://www.depthsecurity.com/blog/exploitation-xml-external-entity-xxe-injection/

[^43]: https://rhinosecuritylabs.com/penetration-testing/xpath-injection-attack-defense-techniques/

[^44]: https://www.exploit-db.com/docs/english/42593-command-injection---shell-injection.pdf

[^45]: https://knowledge-base.secureflag.com/vulnerabilities/cross_site_scripting/cross_site_scripting_php.html

[^46]: https://help.fluidattacks.com/portal/en/kb/articles/criteria-fixes-php-010

[^47]: https://support.detectify.com/support/solutions/articles/48001048941-cross-site-scripting

[^48]: https://gist.github.com/nu11secur1ty/9e7e27cae3fddde2b03c109c0e18d113

[^49]: https://gist.github.com/tcbutler320/7d376ff6298f60ba9c69886d94a839de

[^50]: https://help.fluidattacks.com/portal/en/kb/articles/criteria-fixes-php-021

[^51]: https://www.brightsec.com/blog/cross-site-scripting-php/

[^52]: https://blog.detectify.com/best-practices/what-is-cross-site-scripting-and-how-can-you-fix-it/

[^53]: https://github.com/amir-h-fallahi/xpath-injection/blob/main/xpath.php

[^54]: https://phpsecurity.readthedocs.io/en/latest/Cross-Site-Scripting-(XSS).html

[^55]: https://www.getastra.com/blog/911/php-sql-injection-all-you-need-to-know/

[^56]: https://www.formget.com/sql-injection-prevention-in-php-with-mysqli/

[^57]: https://www.youtube.com/watch?v=cgwWpd4SqIM

[^58]: https://www.tempmail.us.com/en/php/preventing-sql-injection-in-php-best-practices-and-techniques

[^59]: https://bytescout.com/blog/prevent-solve-test-sql-injection-php.html

[^60]: https://www.fromdev.com/2024/09/how-to-prevent-sql-injection-in-php-a-comprehensive-guide.html

[^61]: https://shiflett.org/articles/sql-injection

[^62]: https://symfonycasts.com/screencast/php-ep3/sql-injection-prepared-statements

[^63]: https://phppot.com/php/prevent-sql-injection-php/

[^64]: https://security.stackexchange.com/questions/119727/sql-injection-vulnerability-when-using-prepared-statements-in-php

[^65]: https://accreditly.io/articles/handling-sql-injection-prevention-in-php

[^66]: https://blog.51cto.com/systemerror/1030895

[^67]: https://brightsec.com/blog/cross-site-scripting-php/

[^68]: https://www.w3docs.com/snippets/php/xss-filtering-function-in-php.html

[^69]: https://www.invicti.com/learn/stored-xss-persistent-cross-site-scripting/

[^70]: https://www.theurbanpenguin.com/php-xss-example-and-prevention/

[^71]: https://brightsec.com/blog/php-sql-injection/

[^72]: https://www.brightsec.com/blog/php-sql-injection/?ya_src=serp300

[^73]: https://teamtreehouse.com/community/sql-injection-with-php

[^74]: https://www.youtube.com/watch?v=wJkHuCuYxz4

[^75]: https://tecadmin.net/how-to-prevent-sql-injection-in-php-using-prepared-statements/

[^76]: https://www.youtube.com/watch?v=mkUEyrqYU7E

[^77]: https://www.w3schools.com/php/php_mysql_prepared_statements.asp
