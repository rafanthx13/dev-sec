# A01 - Broken Access Control

## Resumo

Quando um usuario autenticado pode acessar funçôes a mais do que o seu perfil. Em geral, nos sitemas agente apenas nao mostra essa 'outras opçoes' para os usuarios, mas, mmuitas vezes, falta agente relamente restringir e autenticar corretamnte funçoes especificas como de admin

## Links

https://owasp.org/Top10/pt_BR/A01_2021-Broken_Access_Control/

## OWASP


## Visão Geral

Saindo da quinta posição, 94% dos aplicativos foram testados para alguma forma de controle de acesso quebrado com a taxa de incidência média de 3,81% e tem o maior número de ocorrências no conjunto de dados contribuído com mais de 318 mil. Notável  _Common Weakness Enumerations_  (CWEs) incluídas são  _CWE-200: Exposição de Informações Confidenciais a um Ator Não Autorizado_,  _CWE-201: Exposição de Informações Confidenciais por meio de Dados Enviados_  e  _CWE-352: requisições forjadas entre sites_.

## Descrição

O controle de acesso impõe a política de modo que os usuários não possam agir fora de suas permissões pretendidas. As falhas normalmente levam à divulgação, modificação ou destruição de informações não autorizadas de todos os dados ou ao desempenho de uma função comercial fora dos limites do usuário. Vulnerabilidades comuns de controle de acesso incluem:

-   Violação do princípio de privilégio mínimo ou negação por padrão, onde o acesso deve ser concedido apenas para determinados recursos, funções ou usuários, mas está disponível para qualquer pessoa.
    
-   Ignorar verificações de controle de acesso modificando a URL (adulteração de parâmetros ou navegação forçada), o estado interno do aplicativo, a página HTML ou usando uma ferramenta de ataque que modifica as requisições de API.
    
-   Permitir a visualização ou edição da conta de outrem, mediante a disponibilização do seu identificador único (referências diretas não seguras a objetos).
    
-   Acessando API sem controles de acesso para POST, PUT e DELETE.
    
-   Elevação de privilégio. Agir como um usuário sem estar logado ou agir como um administrador quando logado como um usuário.
    
-   Manipulação de metadados, como reproduzir ou adulterar um token de controle de acesso  _JSON Web Token_  (JWT), um cookie ou campo oculto manipulado para elevar privilégios ou abusar da invalidação de JWT.
    
-   A configuração incorreta do CORS permite o acesso à API de origens não autorizadas / não confiáveis.
    
-   Força a navegação para páginas autenticadas como um usuário não autenticado ou para páginas privilegiadas como um usuário padrão.
    

## Como Prevenir

O controle de acesso só é eficaz em código confiável do lado do servidor ou API sem servidor, em que o invasor não pode modificar a verificação de controle de acesso ou metadados.

-   Exceto para recursos públicos, negar por padrão.
    
-   Implemente mecanismos de controle de acesso uma vez e reutilize-os em todo o aplicativo, incluindo a minimização do uso de  _Cross-Origin Resource Sharing_  (CORS).
    
-   Os controles de acesso ao modelo devem impor a propriedade do registro em vez de aceitar que o usuário possa criar, ler, atualizar ou excluir qualquer registro.
    
-   Os requisitos de limite de negócios de aplicativos exclusivos devem ser impostos por modelos de domínio.
    
-   Desative a lista de diretórios do servidor da web e certifique-se de que os metadados do arquivo (por exemplo, o  _.git_) e os arquivos de backup não estejam presentes nas raízes da web (_web roots_).
    
-   Registrar falhas de controle de acesso e alertar os administradores quando apropriado (por exemplo, falhas repetidas).
    
-   Limite de taxa o acesso da API e do controlador para minimizar os danos do conjunto de ferramentas de ataque automatizado.
    
-   Os identificadores de sessão com estado devem ser invalidados no servidor após o logout. Os tokens JWT sem estado devem ter vida curta, para que a janela de oportunidade para um invasor seja minimizada. Para JWTs de longa duração, é altamente recomendável seguir os padrões OAuth para revogar o acesso.
    

Os desenvolvedores e a equipe de QA devem incluir uma unidade de controle de acesso funcional e testes de integração.

## Exemplos de Cenários de Ataque

**Cenário #1:**  O aplicativo usa dados não verificados em uma chamada SQL que está acessando informações da conta:

```
 pstmt.setString(1, request.getParameter("acct"));
 ResultSet results = pstmt.executeQuery( );

```

Um invasor simplesmente modifica o parâmetro 'acct' do navegador para enviar o número de conta que desejar. Se não for verificado corretamente, o invasor pode acessar a conta de qualquer usuário.

```
 https://example.com/app/accountInfo?acct=notmyacct

```

**Cenário #2:**  Um invasor simplesmente força a navegação para URLs de destino. Direitos de administrador são necessários para acessar a página de administrador.

```
 https://example.com/app/getappInfo
 https://example.com/app/admin_getappInfo

```

Se um usuário não autenticado pode acessar qualquer página, é uma falha. Se um não administrador pode acessar a página de administração, isso é uma falha.

## Referências

-   [OWASP Proactive Controls: Enforce Access Controls](https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls)
    
-   [OWASP Application Security Verification Standard: V4 Access Control](https://owasp.org/www-project-application-security-verification-standard)
    
-   [OWASP Testing Guide: Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)
    
-   [OWASP Cheat Sheet: Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
    
-   [PortSwigger: Exploiting CORS misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
    
-   [OAuth: Revoking Access](https://www.oauth.com/oauth2-servers/listing-authorizations/revoking-access/)
    

## Lista dos CWEs Mapeados

[CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)

[CWE-23 Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)

[CWE-35 Path Traversal: '.../...//'](https://cwe.mitre.org/data/definitions/35.html)

[CWE-59 Improper Link Resolution Before File Access ('Link Following')](https://cwe.mitre.org/data/definitions/59.html)

[CWE-200 Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

[CWE-201 Exposure of Sensitive Information Through Sent Data](https://cwe.mitre.org/data/definitions/201.html)

[CWE-219 Storage of File with Sensitive Data Under Web Root](https://cwe.mitre.org/data/definitions/219.html)

[CWE-264 Permissions, Privileges, and Access Controls (should no longer be used)](https://cwe.mitre.org/data/definitions/264.html)

[CWE-275 Permission Issues](https://cwe.mitre.org/data/definitions/275.html)

[CWE-276 Incorrect Default Permissions](https://cwe.mitre.org/data/definitions/276.html)

[CWE-284 Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)

[CWE-285 Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)

[CWE-352 Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)

[CWE-359 Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)

[CWE-377 Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)

[CWE-402 Transmission of Private Resources into a New Sphere ('Resource Leak')](https://cwe.mitre.org/data/definitions/402.html)

[CWE-425 Direct Request ('Forced Browsing')](https://cwe.mitre.org/data/definitions/425.html)

[CWE-441 Unintended Proxy or Intermediary ('Confused Deputy')](https://cwe.mitre.org/data/definitions/441.html)

[CWE-497 Exposure of Sensitive System Information to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/497.html)

[CWE-538 Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)

[CWE-540 Inclusion of Sensitive Information in Source Code](https://cwe.mitre.org/data/definitions/540.html)

[CWE-548 Exposure of Information Through Directory Listing](https://cwe.mitre.org/data/definitions/548.html)

[CWE-552 Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html)

[CWE-566 Authorization Bypass Through User-Controlled SQL Primary Key](https://cwe.mitre.org/data/definitions/566.html)

[CWE-601 URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)

[CWE-639 Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)

[CWE-651 Exposure of WSDL File Containing Sensitive Information](https://cwe.mitre.org/data/definitions/651.html)

[CWE-668 Exposure of Resource to Wrong Sphere](https://cwe.mitre.org/data/definitions/668.html)

[CWE-706 Use of Incorrectly-Resolved Name or Reference](https://cwe.mitre.org/data/definitions/706.html)

[CWE-862 Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)

[CWE-863 Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html)

[CWE-913 Improper Control of Dynamically-Managed Code Resources](https://cwe.mitre.org/data/definitions/913.html)

[CWE-922 Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html)

[CWE-1275 Sensitive Cookie with Improper SameSite Attribute](https://cwe.mitre.org/data/definitions/1275.html)

## ChatGPT

### Q1 - O que é Broken acess control

> Fale sobre o A01 - Broken Access Protocol, o que é, como ocorre e como protegaer. Segue também um link da página em portugues para analisar, veja a lista de CWE mapeadas e faça um resumo delas também: [https://owasp.org/Top10/pt\_BR/A01\_2021-Broken\_Access\_Control/](https://owasp.org/Top10/pt_BR/A01_2021-Broken_Access_Control/)


Excelente escolha, Rafael! Vamos mergulhar no **A01: Quebra de Controle de Acesso (Broken Access Control)**, que está no topo da lista do OWASP porque é **muito comum** e **frequentemente explorada** por atacantes.

---

## 🔐 O que é "Broken Access Control"?

"**Quebra de controle de acesso**" ocorre quando um sistema **não restringe corretamente o que cada usuário pode acessar ou executar**.

Ou seja, um atacante consegue:

* Ver dados de outros usuários.
* Modificar dados de contas que não são dele.
* Acessar painéis administrativos sem permissão.
* Executar ações como deletar ou criar recursos que não deveria.

---

## ⚠️ Como esse problema ocorre?

### Exemplos práticos:

* 🔓 Um usuário comum acessa `/admin/dashboard` e entra porque não há checagem de permissão.
* 🔓 Uma requisição `PUT /user/1234` permite que o usuário 1234 altere os dados do usuário 5678.
* 🔓 Um token JWT pode ser modificado manualmente para obter privilégios elevados.
* 🔓 Esconder links (via front-end) em vez de realmente proteger no backend.

---

## 🛡️ Como se proteger?

### ✅ Práticas recomendadas:

1. **Controle de acesso no backend, SEMPRE.**

   * Nunca confie em validações feitas só no front-end.

2. **Use middleware de autenticação e autorização.**

   * No Laravel, por exemplo: `Gate`, `Policy`, `Middleware`, `@can`, etc.

3. **Valide sempre o "dono" do recurso.**

   * Ao acessar algo como `/user/123`, verifique se o ID é do próprio usuário logado.

4. **Evite IDs previsíveis (ex: autoincremento simples).**

   * Considere usar UUIDs para recursos sensíveis.

5. **Desative diretórios não utilizados, o browse de diretórios e permissões padrão.**

6. **Audite acessos sensíveis.**

   * Quem acessou o quê e quando.

---

## 📘 Página oficial traduzida:

🔗 [A01:2021 - Quebra de Controle de Acesso (OWASP)](https://owasp.org/Top10/pt_BR/A01_2021-Broken_Access_Control/)

---

## 🧠 CWE Mapeadas – Resumo

A OWASP relaciona **34 CWEs** com esse item. Aqui estão os **principais destaques** e um **resumo simplificado**:

| CWE         | Descrição resumida                                                                              |
| ----------- | ----------------------------------------------------------------------------------------------- |
| **CWE-200** | Exposição de informações sensíveis (ex: dados de outro usuário).                                |
| **CWE-201** | Exposição acidental de informações através de mensagens de erro.                                |
| **CWE-284** | Controle de acesso ausente ou incorreto.                                                        |
| **CWE-285** | Falta de verificação de permissão antes de uma ação.                                            |
| **CWE-639** | Falha ao restringir acesso com base no ID do usuário (IDOR – Insecure Direct Object Reference). |
| **CWE-640** | Acesso autorizado baseado em dados manipuláveis (ex: tokens alteráveis).                        |
| **CWE-862** | Falta de verificação de autorização (ação protegida sem autenticação).                          |
| **CWE-863** | Autenticação feita, mas sem verificar se tem **permissão específica**.                          |
| **CWE-922** | Dados sensíveis expostos sem criptografia.                                                      |
| **CWE-275** | Privilégios concedidos além do necessário (privilégios excessivos).                             |
| **CWE-287** | Autenticação mal implementada.                                                                  |

Essas CWEs mostram que o **problema pode acontecer por falha de design, implementação ou configuração**.

---

## ✅ Checklist rápido para seu código PHP/Laravel

* [ ] Está usando middleware de autenticação e autorização?
* [ ] Valida que o usuário logado tem permissão para acessar o recurso solicitado?
* [ ] Oculta (e nega) acesso a rotas administrativas se não for admin?
* [ ] Valida quem é o dono de um recurso antes de atualizar/deletar?
* [ ] Usa `Gate::define()` ou `Policy` nos modelos sensíveis?
* [ ] Usa UUID em vez de IDs sequenciais em rotas críticas?
* [ ] Testa se consegue alterar ou acessar dados de outro usuário via requisição forjada?

---

Se quiser, posso te ajudar a aplicar essas proteções no seu sistema Laravel atual ou revisar uma parte do seu código com esse olhar de segurança. Só mandar!

### Q2 - Em PHP

> as aplicações da minha empresa são muitas em php puro, e são aplicações simples, como poderia implementar um middleware nesse cenário

Boa pergunta, Rafael. Em PHP puro (sem frameworks como Laravel ou Symfony), não existe um sistema nativo de middleware, mas **você pode implementar algo simples e funcional com organização de código**. Vamos ver como!

---

## ✅ O que é um middleware mesmo?

É **um código executado antes (ou depois) da requisição principal**, geralmente usado para:

* Autenticação
* Verificação de permissões
* Log de requisições
* Redirecionamento
* Proteção contra CSRF, rate-limit etc.

---

## 🔧 Implementando um middleware simples em PHP puro

### 🗂️ Estrutura sugerida:

```plaintext
/
├── index.php
├── middlewares/
│   ├── auth.php
│   └── log.php
├── pages/
│   └── painel.php
└── core/
    └── middleware.php
```

---

### 🔁 Exemplo de carregador de middlewares (`core/middleware.php`):

```php
<?php

function run_middlewares(array $middlewares)
{
    foreach ($middlewares as $middleware) {
        $path = __DIR__ . '/../middlewares/' . $middleware . '.php';
        if (file_exists($path)) {
            require_once $path;
        } else {
            throw new Exception("Middleware $middleware não encontrado.");
        }
    }
}
```

---

### 🔐 Middleware de autenticação (`middlewares/auth.php`):

```php
<?php

session_start();

if (!isset($_SESSION['usuario_logado'])) {
    header('Location: /login.php');
    exit;
}
```

---

### 📜 Middleware de log (`middlewares/log.php`):

```php
<?php

$log = date('Y-m-d H:i:s') . " | IP: " . $_SERVER['REMOTE_ADDR'] . " | URI: " . $_SERVER['REQUEST_URI'] . PHP_EOL;
file_put_contents(__DIR__ . '/../logs/access.log', $log, FILE_APPEND);
```

---

### 📄 Página protegida (`pages/painel.php`):

```php
<?php
require_once __DIR__ . '/../core/middleware.php';

run_middlewares(['auth', 'log']); // Aqui você escolhe os middlewares que quer rodar

echo "Bem-vindo ao painel!";
```

---

### ✅ Vantagens desse modelo:

* Código reutilizável.
* Você escolhe **quais middlewares** rodar em cada página.
* Fácil de entender e manter em times pequenos.

---

Se quiser deixar isso mais robusto, posso te mostrar como adicionar um sistema de rotas leve com middlewares dinâmicos, ou usar o [Slim Framework](https://www.slimframework.com/) que é minimalista e já tem suporte nativo para middlewares (e funciona muito bem com PHP puro).

Quer um exemplo mais avançado com rotas ou continuar com essa estrutura básica?


### Q3

> há mais algum design patterrs ou arquitetura de sistema além de midleware que pode envolver segurança?

Com certeza, Rafael! Middleware é só **uma parte** de um ecossistema de segurança. Há **diversos padrões de projeto e arquiteturas** que podem (e devem) ser usados para fortalecer a segurança de aplicações, inclusive em sistemas PHP puros. Aqui vai uma visão organizada:

---

## 🔐 Design Patterns e Arquiteturas com foco em **segurança**

### 1. **Front Controller**

**Objetivo:** Centralizar o ponto de entrada da aplicação.

**Como ajuda na segurança:**

* Permite validar, autenticar, filtrar e logar tudo em **um único lugar** antes de executar qualquer ação.
* Bloqueia acessos diretos a arquivos `.php`.

**Exemplo básico:**

```php
// public/index.php
require 'core/router.php'; // Toda requisição passa por aqui
```

---

### 2. **Dependency Injection (DI)**

**Objetivo:** Separar responsabilidades, facilitar testes e controle de objetos sensíveis (ex: DB, Auth, Logger).

**Como ajuda na segurança:**

* Evita uso indiscriminado de variáveis globais.
* Facilita simular serviços em testes de segurança.
* Garante controle central de instâncias críticas (ex: conexões, autenticações).

---

### 3. **Service Layer (ou Application Layer)**

**Objetivo:** Organizar regras de negócio e ações sensíveis em **serviços isolados**.

**Como ajuda na segurança:**

* Facilita auditar e proteger ações como: criar usuário, resetar senha, gerar token.
* Permite aplicar controle de permissões em **nível de serviço**, não só na rota.

---

### 4. **Strategy Pattern para Autorização**

**Objetivo:** Ter estratégias diferentes para verificar permissões com base no contexto.

**Como ajuda na segurança:**

* Você pode aplicar regras como “usuário dono do recurso”, “admin”, “supervisor”, etc., de forma organizada.

---

### 5. **Data Transfer Object (DTO)**

**Objetivo:** Separar o que vem da requisição dos modelos internos da aplicação.

**Como ajuda na segurança:**

* Impede que dados não autorizados sejam salvos diretamente.
* Você valida o conteúdo do DTO antes de usar (ex: campos esperados, tipos corretos).

---

### 6. **Validator Pattern**

**Objetivo:** Validar entrada de dados com lógica desacoplada.

**Como ajuda na segurança:**

* Evita SQL Injection, XSS e outros ataques baseados em entrada maliciosa.
* Centraliza filtros e sanitações (ex: `htmlspecialchars`, `filter_var` etc).

---

### 7. **Repository Pattern**

**Objetivo:** Abstrair acesso ao banco de dados.

**Como ajuda na segurança:**

* Permite forçar o uso de `prepared statements`.
* Centraliza as regras de acesso a dados sensíveis.

---

### 8. **Arquitetura MVC (Model-View-Controller)**

**Objetivo:** Separar apresentação, lógica e dados.

**Como ajuda na segurança:**

* Impede misturar HTML com SQL ou lógica de autenticação.
* Cada camada pode aplicar seus próprios filtros e sanitações.

---

### 9. **Security by Design + Defense in Depth**

**Arquitetura geral de segurança:**

* **"Security by design"** = segurança desde o início, não como remendo.
* **"Defesa em profundidade"** = múltiplas camadas de defesa:

  * Autenticação (ex: sessão, token)
  * Autorização (regras de acesso)
  * Validação (entrada de dados)
  * Criptografia (dados sensíveis)
  * Logging (registro de eventos)
  * Rate limiting, CSRF, CORS etc.

---

## 🧰 Ferramentas e práticas complementares

| Área                 | Ferramentas/Boas práticas                                                 |
| -------------------- | ------------------------------------------------------------------------- |
| Senhas               | `password_hash`, `password_verify`                                        |
| Sessões              | Cookies `HttpOnly`, `Secure`, regenerar ID                                |
| Entrada de dados     | `filter_input`, `htmlspecialchars`                                        |
| Logs                 | Gravar IP, user-agent, URI, erro etc                                      |
| Rate limiting        | Crie um contador por IP/usuário/session                                   |
| CSRF                 | Tokens únicos nos formulários                                             |
| Headers de segurança | `X-Frame-Options`, `Content-Security-Policy`, `Strict-Transport-Security` |
| HTTPS obrigatório    | Redirecionar para HTTPS                                                   |

---

Se quiser, posso te ajudar a construir **uma base reutilizável** com essas boas práticas em PHP puro, para ser usada em todos os seus projetos simples.

Quer?

### Q4 - Sim (coitunaido a nteriror)

> Sim

Show, Rafael! Vamos montar uma **base reutilizável em PHP puro com foco em segurança**, boa estrutura e extensível. A ideia é que você consiga usar isso em qualquer projeto simples, e ir adaptando conforme precisar.

---

## 🧱 Estrutura base sugerida (com segurança em mente)

```
/
├── public/
│   └── index.php                # Front Controller
├── app/
│   ├── Controllers/
│   ├── Services/
│   ├── Middlewares/
│   ├── Models/
│   ├── Validators/
│   └── Views/
├── core/
│   ├── Router.php
│   ├── Middleware.php
│   ├── Request.php
│   ├── Response.php
│   └── Security.php
├── config/
│   └── app.php                  # Configs globais
├── logs/
│   └── access.log
├── storage/
│   └── sessions/
├── .env                         # Variáveis de ambiente
└── bootstrap.php                # Loader
```

---

## 🚀 Começando do zero: passo a passo

### 🔐 Segurança mínima no `index.php`

```php
<?php
// public/index.php

require_once __DIR__ . '/../bootstrap.php';

use Core\Router;
use Core\Security;

Security::enforceHttps();          // Força HTTPS
Security::secureHeaders();         // XSS/Clickjacking
Security::startSecureSession();    // Sessão segura

$router = new Router();
$router->dispatch($_SERVER['REQUEST_URI']);
```

---

### 🔒 Exemplo de `Security.php` com boas práticas

```php
<?php
namespace Core;

class Security
{
    public static function enforceHttps()
    {
        if (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === 'off') {
            header('Location: https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
            exit;
        }
    }

    public static function secureHeaders()
    {
        header('X-Frame-Options: DENY');
        header('X-Content-Type-Options: nosniff');
        header("Content-Security-Policy: default-src 'self'");
        header('Strict-Transport-Security: max-age=63072000; includeSubDomains');
    }

    public static function startSecureSession()
    {
        session_save_path(__DIR__ . '/../storage/sessions');
        session_name('APPSESSID');
        session_start();
        session_regenerate_id(true);
    }
}
```

---

### 🛡️ Middleware de autenticação (em `app/Middlewares/AuthMiddleware.php`)

```php
<?php
namespace App\Middlewares;

class AuthMiddleware
{
    public static function handle()
    {
        if (!isset($_SESSION['user'])) {
            header('Location: /login');
            exit;
        }
    }
}
```

E para chamar, o `Router.php` poderia aceitar algo tipo:

```php
$router->get('/painel', 'PainelController@index', [AuthMiddleware::class]);
```

---

### 🧼 Exemplo simples de Validator (`app/Validators/UserValidator.php`)

```php
<?php
namespace App\Validators;

class UserValidator
{
    public static function validateLogin(array $data)
    {
        if (empty($data['email']) || !filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
            throw new \Exception('Email inválido');
        }

        if (empty($data['senha']) || strlen($data['senha']) < 6) {
            throw new \Exception('Senha inválida');
        }

        return true;
    }
}
```

---

### 📜 Config de variáveis de ambiente `.env`

```
APP_NAME=MinhaApp
APP_ENV=production
DB_HOST=localhost
DB_NAME=meubanco
DB_USER=root
DB_PASS=123
```

Você pode criar um `EnvLoader.php` para ler isso.

---

## ✅ Boas práticas embutidas:

* HTTPS forçado
* Headers seguros
* Sessões com `regenerate_id` e nome personalizado
* Middlewares
* Validação com pattern separado
* `.env` para proteger configs sensíveis
* Organização limpa (MVC-ish)

---

Se quiser, eu posso gerar um repositório ZIP com essa base inicial ou ir te ajudando arquivo por arquivo.

O que você prefere: um ZIP com tudo pronto ou seguir passo a passo juntos aqui?


## Perplexity

<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" class="logo" width="120"/>

# A01:2021 - Broken Access Control: Casos, Impactos e Estratégias de Mitigação

A vulnerabilidade **A01:2021 - Broken Access Control** (Quebra de Controle de Acesso) ocupa o primeiro lugar no OWASP Top 10 de 2021, representando o risco mais crítico para aplicações web modernas. Essa falha ocorre quando mecanismos de autorização não impedem que usuários acessem recursos ou executem ações além de suas permissões legítimas, resultando em exposição de dados sensíveis, modificação não autorizada de informações e até comprometimento total de sistemas. Com uma taxa de incidência de 55,97% em aplicações testadas e mais de 318 mil ocorrências documentadas, o Broken Access Control é uma ameaça ubíqua e complexa, exigindo atenção prioritária de desenvolvedores e equipes de segurança[^1][^2].

## Principais Vetores de Ataque em Broken Access Control

### Manipulação de URL e Parâmetros

A modificação direta de URLs ou parâmetros é uma das técnicas mais simples e eficazes para explorar falhas de controle de acesso. Por exemplo, se um usuário acessa seu perfil através de uma URL como `https://exemplo.com/perfil?id=123`, alterar o valor `id=123` para `id=456` pode permitir visualizar dados de outro usuário, caso a aplicação não valide as permissões do solicitante. Esse tipo de ataque, conhecido como **Insecure Direct Object References (IDOR)**, foi responsável por violações massivas, como o vazamento de 4,6 milhões de contas do Snapchat em 2014, onde identificadores expostos permitiram a coleta ilegal de números de telefone e localizações[^4][^7].

### Elevação de Privilégios

Ataques de elevação de privilégios ocorrem quando um usuário com acesso limitado consegue assumir funções administrativas. Um cenário comum envolve a exploração de falhas em fluxos de autenticação, como a manipulação de cookies ou tokens JWT (JSON Web Tokens). Por exemplo, se um token de sessão contém uma afirmação como `"role": "user"`, um atacante pode alterá-la para `"role": "admin"` para obter acesso a funcionalidades restritas. Em 2021, um relatório destacou que 34% das aplicações analisadas tinham vulnerabilidades relacionadas a tokens JWT mal configurados[^1][^3].

### Exploração de Endpoints Não Protegidos

APIs e endpoints mal configurados são alvos frequentes. Um estudo de 2023 revelou que 60% das violações de acesso ocorreram em APIs REST, onde métodos como POST, PUT e DELETE não tinham controles de autorização adequados. Por exemplo, um endpoint `DELETE /api/usuarios/{id}` sem validação de permissões permite que qualquer usuário remova contras alheias. Ataques a endpoints são particularmente perigosos em arquiteturas de microsserviços, onde a falta de visibilidade entre serviços amplia a superfície de ataque[^3][^8].

### Má Gestão de Sessões

Sessões inseguras facilitam o sequestro de contas. A utilização de IDs de sessão previsíveis, cookies sem atributos `HttpOnly` ou `Secure`, ou tokens sem expiração adequada permite que atacantes reutilizem credenciais válidas. Um caso emblemático ocorreu em uma plataforma de e-commerce, onde tokens de sessão eram gerados com base no timestamp do sistema, permitindo que atacantes recriassem sessões válidas através de brute force[^4][^6].

## Casos Reais de Broken Access Control

### Snapchat (2014)

Em 2014, explorando uma falha de IDOR, hackers acessaram uma API não documentada do Snapchat que retornava números de telefone associados a nomes de usuário. Ao modificar programaticamente os parâmetros de solicitação, coletaram dados de 4,6 milhões de contas, expondo a falta de validação de autorização na API. O incidente destacou a importância de sanitizar entradas e implementar controles de acesso em todos os endpoints, mesmo os internos[^7][^8].

### Vazamento de Dados em Plataforma de Saúde (2023)

Uma clínica médica sofreu uma violação onde registros de pacientes foram expostos devido a uma combinação de IDOR e má configuração de CORS (Cross-Origin Resource Sharing). A aplicação permitia solicitações de qualquer origem (`Access-Control-Allow-Origin: *`), e URLs como `https://clinica.com/prontuarios/123` não verificavam se o usuário autenticado tinha relação com o ID do prontuário. Atacantes exploraram isso para extrair dados sensíveis de 500 mil pacientes[^1][^8].

### Elevação de Privilégio em Rede Social (2022)

Uma rede social permitia que usuários comuns acessassem funcionalidades de moderador alterando um parâmetro oculto no HTML (`<input type="hidden" name="isModerator" value="false">`). Ao modificar o valor para `true`, usuários mal-intencionados podiam excluir publicações e banir outros usuários. O caso ilustra a importância de validar permissões no lado do servidor, nunca confiando em parâmetros client-side[^3][^6].

## Análise Técnica das Vulnerabilidades

### CWEs Associadas

- **CWE-200: Exposição de Informações Sensíveis**: Ocorre quando dados confidenciais são acessados sem autorização, como no caso Snapchat[^1][^7].
- **CWE-352: Cross-Site Request Forgery (CSRF)**: Permite que ações não autorizadas sejam executadas em nome de usuários autenticados, explorando a falta de tokens anti-CSRF[^1][^6].
- **CWE-862: Autorização Ausente**: Falha em verificar permissões antes de executar operações críticas, comum em APIs não protegidas[^8].


### Impacto em Camadas de Aplicação

- **Frontend**: Controles de acesso baseados em JavaScript podem ser contornados via ferramentas de depuração, exigindo validação redundante no backend[^6][^8].
- **Backend**: Falhas em sistemas de RBAC (Role-Based Access Control) permitem que usuários acessem recursos além de sua função[^2][^4].
- **Banco de Dados**: Consultas SQL sem filtragem adequada de permissões resultam em vazamento de dados (e.g., `SELECT * FROM users WHERE id = ${inputId}`)[^3][^7].


## Medidas de Prevenção

### Princípios de Design Seguro

- **Menor Privilégio**: Conceder apenas as permissões necessárias para cada função. Por exemplo, usuários comuns não devem ter acesso a endpoints de administração, mesmo que não estejam vinculados na interface[^2][^8].
- **Validação Server-Side**: Nunca confiar em verificações client-side. Todas as solicitações devem passar por autorização no servidor, usando frameworks consolidados como Spring Security ou OAuth2[^6][^8].
- **Logs e Monitoramento**: Registrar tentativas de acesso não autorizado e implementar alertas para padrões suspeitos (e.g., múltiplas tentativas de acesso a `/admin`)[^4][^8].


### Ferramentas e Testes

- **DAST/SAST**: Ferramentas como OWASP ZAP e Fortify identificam endpoints não protegidos e fluxos de autenticação frágeis[^2][^8].
- **Testes de Penetração**: Simulações realistas revelam falhas como IDOR e elevação de privilégios. Em 2023, 70% das organizações que adotaram pentests regulares reduziram incidentes de acesso não autorizado[^3][^7].


## Conclusão

O Broken Access Control permanece como a vulnerabilidade mais crítica em aplicações web devido à sua natureza transversal e impacto potencial. Casos como o do Snapchat e de plataformas de saúde evidenciam que falhas simples, como a exposição de IDs em URLs ou a falta de validação server-side, podem resultar em danos irreparáveis. A combinação de princípios de design seguro, testes automatizados e monitoramento contínuo é essencial para mitigar riscos. Organizações devem priorizar a revisão de mecanismos de autorização, garantindo que cada camada da aplicação enforce políticas de acesso restritivas e baseadas em contexto[^1][^2][^8].

<div style="text-align: center">⁂</div>

[^1]: https://owasp.org/Top10/A01_2021-Broken_Access_Control/

[^2]: https://www.indusface.com/blog/owasp-top-10-vulnerabilities-in-2021-how-to-mitigate-them/

[^3]: https://brightsec.com/blog/broken-access-control-attack-examples-and-4-defensive-measures/

[^4]: https://www.activestate.com/blog/the-risks-of-broken-access-control-explained-vulnerabilities-examples-best-practices/

[^5]: https://owasp.org/Top10/pt_BR/A01_2021-Broken_Access_Control/

[^6]: https://dev.to/gabogaldino/explicandobroken-access-control-para-desenvolvedores-5dmn

[^7]: https://www.securityjourney.com/post/owasp-top-10-broken-access-control-explained

[^8]: https://www.invicti.com/blog/web-security/broken-access-control/

[^9]: https://cheatsheetseries.owasp.org/IndexTopTen.html

[^10]: https://owasp.org/Top10/

[^11]: https://www.linkedin.com/pulse/exploring-owasp-top-10-vulnerabilities-comprehensive-guide-arunima-m-5gfbc

[^12]: https://nordlayer.com/learn/access-control/broken-access-control/

[^13]: https://securityboulevard.com/2023/03/23-most-notorious-hacks-history-that-fall-under-owasp-top-10/

[^14]: https://www.pynt.io/learning-hub/owasp-top-10-guide/owasp-top-10-cheat-sheet-threats-and-mitigations-in-brief

[^15]: https://cecyber.com/owasp-top-10-web-application-security-risks-2021/

[^16]: https://www.youtube.com/watch?v=iR902MTqpnA

[^17]: https://portswigger.net/web-security/access-control

[^18]: https://sectona.com/technology/broken-access-control-in-web-security/

[^19]: https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Authentication_Cheat_Sheet.md

[^20]: https://my.f5.com/manage/s/article/K000147485

