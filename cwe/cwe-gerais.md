# CWE

## CWE gerais

> by chatpgt: Quais sao as cwe mais importantes, famosas

Claro! Aqui estão exemplos **práticos em PHP** para as **principais CWEs** que mencionei, com explicações e sugestões de correção. Isso vai te ajudar a identificar e corrigir falhas no seu próprio código:

---

## 🔥 CWE-79: **Cross-Site Scripting (XSS)**

**Exemplo vulnerável:**

```php
// O valor vem de uma query string como ?nome=<script>alert('XSS')</script>
echo "Olá, " . $_GET['nome'];
```

**Exploração:** código JavaScript malicioso é executado no navegador da vítima.

**Correção:**

```php
echo "Olá, " . htmlspecialchars($_GET['nome'], ENT_QUOTES, 'UTF-8');
```

---

## 💥 CWE-89: **SQL Injection**

**Exemplo vulnerável:**

```php
// ?id=1 OR 1=1
$id = $_GET['id'];
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = $id");
```

**Exploração:** o atacante pode injetar comandos SQL e acessar todo o banco.

**Correção com prepared statement:**

```php
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $id);
$stmt->execute();
```

---

## 🚪 CWE-287: **Improper Authentication**

**Exemplo vulnerável:**

```php
// Assume que se o campo "user" está presente, o usuário está autenticado
if (isset($_POST['user'])) {
    $_SESSION['logado'] = true;
}
```

**Problema:** não verifica senha ou autenticação real.

**Correção:**

```php
$user = $_POST['user'];
$pass = $_POST['password'];
$stmt = $conn->prepare("SELECT senha_hash FROM usuarios WHERE user = ?");
$stmt->bind_param("s", $user);
$stmt->execute();
$result = $stmt->get_result();
$row = $result->fetch_assoc();

if ($row && password_verify($pass, $row['senha_hash'])) {
    $_SESSION['logado'] = true;
}
```

---

## 🗂 CWE-22: **Path Traversal**

**Exemplo vulnerável:**

```php
// ?file=../../../../etc/passwd
$file = $_GET['file'];
readfile("uploads/" . $file);
```

**Exploração:** acesso a arquivos arbitrários do sistema.

**Correção:**

```php
$filename = basename($_GET['file']); // remove diretórios
$path = realpath("uploads/$filename");

if (strpos($path, realpath("uploads")) === 0) {
    readfile($path);
} else {
    http_response_code(403);
}
```

---

## 🧬 CWE-502: **Insecure Deserialization**

**Exemplo vulnerável:**

```php
$data = $_COOKIE['user_data'];
$obj = unserialize($data);
```

**Exploração:** o atacante injeta objetos maliciosos que executam métodos mágicos (`__wakeup`, `__destruct`, etc).

**Correção:**

* **Nunca desserializar dados não confiáveis**.
* Use `json_encode` / `json_decode` em vez de `serialize`.

---

## 🔐 CWE-327: **Uso de criptografia insegura**

**Exemplo vulnerável:**

```php
$hash = md5($senha); // fraco e quebrado
```

**Correção:**

```php
$hash = password_hash($senha, PASSWORD_ARGON2ID);
```

---

## 🛑 CWE-798: **Credenciais Hardcoded**

**Exemplo vulnerável:**

```php
$db_user = 'root';
$db_pass = 'senha123'; // senha escrita no código
```

**Correção:**

```php
$db_user = getenv('DB_USER'); // usar .env ou cofres de segredo
$db_pass = getenv('DB_PASS');
```

---

## 🌐 CWE-601: **Open Redirect**

**Exemplo vulnerável:**

```php
// ?redirect=http://malicioso.com
header("Location: " . $_GET['redirect']);
```

**Correção:**

```php
$whitelist = ['painel.php', 'perfil.php'];
$destino = $_GET['redirect'];

if (in_array($destino, $whitelist)) {
    header("Location: $destino");
} else {
    header("Location: /");
}
```

---

Se quiser, posso criar um **repositório de demonstração em PHP** com todos esses exemplos organizados em pastas por CWE. Deseja isso?


## CWE no contexto PHP e Laravel

>  Monste uma tabela com as cwe mais comuns par ao PHP e para o Laravel: 


Claro, Rafael! Abaixo está uma tabela organizada com as **CWE mais comuns em projetos PHP puro e Laravel**, divididas por tipo de risco, com descrição, exemplos típicos e observações específicas para cada stack.

---

### 📋 **Tabela: CWE mais comuns em PHP e Laravel**

| CWE ID      | Nome da Falha                       | PHP Puro                                                      | Laravel                                               | Observações / Exemplo                                 |
| ----------- | ----------------------------------- | ------------------------------------------------------------- | ----------------------------------------------------- | ----------------------------------------------------- |
| **CWE-79**  | Cross-Site Scripting (XSS)          | `echo $_GET['msg']` sem `htmlspecialchars()`                  | Blade: `{!! $var !!}` ao invés de `{{ $var }}`        | Cuidado com saídas não escapadas                      |
| **CWE-89**  | SQL Injection                       | Uso direto de `$_GET` em `mysqli_query()`                     | Uso de `DB::select("... $input ...")` sem bindings    | Sempre usar prepared statements ou query builder      |
| **CWE-22**  | Path Traversal                      | `readfile($_GET['file'])`                                     | Acesso direto a arquivos em Storage via input externo | Use `basename()` e valide caminhos                    |
| **CWE-287** | Improper Authentication             | Login sem `password_verify()`                                 | Autenticação custom sem validar `Hash::check()`       | Nunca confie só no nome de usuário                    |
| **CWE-798** | Hardcoded Credentials               | Credenciais no código (ex: `senha = "123"`)                   | Credenciais no `.env.example`                         | Use variáveis de ambiente                             |
| **CWE-327** | Uso de Criptografia Fraca           | Uso de `md5()`, `sha1()`                                      | Custom hash em vez de `Hash::make()`                  | Use `password_hash()` ou `Hash::make()`               |
| **CWE-200** | Exposição de Informação Sensível    | Mensagens de erro detalhadas (`ini_set('display_errors', 1)`) | `APP_DEBUG=true` em produção                          | Nunca exponha mensagens técnicas                      |
| **CWE-352** | Cross-Site Request Forgery (CSRF)   | Formulário sem token de proteção                              | Não uso de `@csrf` no Blade                           | Laravel protege automaticamente se usado corretamente |
| **CWE-502** | Insecure Deserialization            | Uso de `unserialize()` com dados externos                     | Jobs, cache ou sessão manipuladas externamente        | Prefira `json_decode()` em dados externos             |
| **CWE-522** | Armazenamento inseguro de senhas    | Guardar senhas em texto plano                                 | Custom auth sem `Hash::make()`                        | Sempre use hash forte com sal automático              |
| **CWE-611** | XXE (XML External Entity Injection) | Uso de `simplexml_load_string()` com XML não validado         | Pouco comum em Laravel, mas atenção com XML em APIs   | Desativar carregamento de entidades externas          |
| **CWE-918** | SSRF (Server-Side Request Forgery)  | `file_get_contents($url)` com entrada externa                 | `Http::get($url)` com dados não validados             | Valide URLs antes de consumir serviços                |
| **CWE-601** | Open Redirect                       | `header("Location: " . $_GET['url'])`                         | `redirect($input)` sem validação                      | Use whitelists de URLs válidas                        |

---

### 🛡️ Recomendações gerais

* **PHP**: sempre sanitize e valide entrada de usuário. Evite funções perigosas (`eval`, `unserialize`, `system`, etc).
* **Laravel**: **muitas proteções já estão inclusas** (CSRF, XSS, SQLi), mas **podem ser burladas se mal utilizadas** (ex: `DB::raw`, `@csrf` ausente, `{{ }}` trocado por `{!! !!}`).
* **Ambos**: nunca exponha `.env`, erros, ou dados sensíveis. Proteja os logs.

---

Se quiser, posso exportar essa tabela em formato `.md`, `.csv` ou `.xlsx` para você incluir no seu repositório ou estudos. Deseja isso?
