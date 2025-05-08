# A02 - Cryptographic Failures

## Resumo

É nao usar criptograia para dados sensivies, ou, se usar, usar uma simples demai s de quebrar.

## Links

https://owasp.org/Top10/pt_BR/A02_2021-Cryptographic_Failures/

## OWASP

## Visão Geral

Subindo uma posição para #2, anteriormente conhecido como  _Exposição de Dados Sensíveis_, que é mais um sintoma amplo do que uma causa raiz, o foco está nas falhas relacionadas à criptografia (ou falta dela). O que muitas vezes leva à exposição de dados confidenciais. Notável  _Common Weakness Enumerations_  (CWEs) incluídas são  _CWE-259: Uso de Senha no Código_,  _CWE-327: Algoritmo Criptográfico Quebrado ou Arriscado_  e  _CWE-331 Entropia Insuficiente_.

## Descrição

A primeira coisa é determinar as necessidades de proteção dos dados em trânsito e armazenados. Por exemplo, senhas, número de cartão de crédito, registros de saúde, informações pessoas e segredos de negócios que requerem proteção extra, principalmente se esses dados se enquadrarem nas leis de privacidade, alguns exemplos são a da Europa General Data Protection Regulation (GDPR) ou regulamentos de proteção de dados financeiros, como PCI Data Security Standard (PCI DSS). Para todos esses dados:

-   Todos os dados são transmitidos em texto não criptografado? Isso diz respeito a protocolos como HTTP, SMTP, FTP também usando atualizações TLS como STARTTLS. O tráfego externo da Internet é perigoso. Verifique todo o tráfego interno, por exemplo, entre balanceadores de carga, servidores da web ou sistemas  _back-end_.
    
-   Algum algoritmo ou protocolo criptográfico antigo ou fraco é usado por padrão ou em código mais antigo?
    
-   As chaves criptográficas padrão em uso, são chaves criptográficas geradas fracas ou reutilizadas, faltando o gerenciamento ou rotação de chaves adequado? As chaves criptográficas são verificadas nos repositórios de código-fonte?
    
-   A criptografia não é aplicada, por exemplo, há alguma diretiva de segurança de cabeçalhos HTTP (navegador) ou cabeçalhos ausentes?
    
-   O certificado do servidor recebido e a cadeia de confiança estão devidamente validados?
    
-   Os vetores de inicialização são ignorados, reutilizados ou não gerados suficientemente seguros para o modo criptográfico de operação? Está em uso um modo de operação inseguro, como o ECB? A criptografia é usada quando a criptografia autenticada é a mais apropriada?
    
-   As senhas estão sendo usadas como chaves criptográficas na ausência de uma função de derivação de chave de base de senha?
    
-   A aleatoriedade é usada para fins criptográficos que não foram projetados para atender aos requisitos criptográficos? Mesmo se a função correta for escolhida, ela precisa ser propagada pelo desenvolvedor e, se não, o desenvolvedor sobrescreveu a forte funcionalidade de propagação incorporada a ela com uma semente que carece de entropia/imprevisibilidade suficiente?
    
-   Estão em uso funções hash obsoletas, como MD5 ou SHA1, ou funções hash não criptográficas usadas quando funções hash criptográficas são necessárias?
    
-   Estão em uso métodos de preenchimento criptográfico obsoletos, como PKCS número 1 v1.5?
    
-   As mensagens de erro criptográficas ou as informações do canal lateral podem ser exploradas, por exemplo, na forma de ataques oracle de preenchimento?
    

Consulte ASVS Crypto (V7), Data Protection (V9) e SSL/TLS (V10)

## Como Prevenir

Faça o seguinte, no mínimo, e consulte as referências:

-   Classifique os dados processados, armazenados ou transmitidos por um aplicativo. Identifique quais dados são confidenciais de acordo com as leis de privacidade, requisitos regulamentares ou necessidades de negócios.
    
-   Não armazene dados confidenciais desnecessariamente. Descarte-o o mais rápido possível ou use tokenização compatível com PCI DSS ou mesmo truncamento. Os dados não retidos não podem ser roubados.
    
-   Certifique-se de criptografar todos os dados confidenciais armazenados.
    
-   Certifique-se de que algoritmos, protocolos e senhas de padrão forte e atualizados estejam em vigor; use o gerenciamento de senhas adequado.
    
-   Criptografe todos os dados em trânsito com protocolos seguros, como TLS com cifras de sigilo de encaminhamento (FS), priorização de cifras pelo servidor e parâmetros seguros. Aplique a criptografia usando diretivas como HTTP Strict Transport Security (HSTS).
    
-   Desative o armazenamento em cache para respostas que contenham dados confidenciais.
    
-   Aplique os controles de segurança necessários de acordo com a classificação de dados.
    
-   Não use protocolos legados, como FTP e SMTP, para transportar dados confidenciais.
    
-   Armazene senhas usando fortes funções de hash adaptáveis e saltadas com um fator de trabalho (fator de atraso), como Argon2, scrypt, bcrypt ou PBKDF2.
    
-   Os vetores de inicialização devem ser escolhidos de acordo com o modo de operação. Para muitos modos, isso significa usar um CSPRNG (gerador de números pseudo-aleatórios criptograficamente seguro). Para modos que requerem um nonce, o vetor de inicialização (IV) não precisa de um CSPRNG. Em todos os casos, o IV nunca deve ser usado duas vezes para uma chave fixa.
    
-   Sempre use criptografia autenticada em vez de apenas criptografia.
    
-   As chaves devem ser geradas de forma criptograficamente aleatória e armazenadas na memória como um  _array_  de  _bytes_. Se uma senha for usada, ela deve ser convertida em uma chave por meio de uma função de derivação de chave de base de senha apropriada.
    
-   Certifique-se de que a aleatoriedade criptográfica seja usada quando apropriado e que não tenha sido usada uma semente de uma forma previsível ou com baixa entropia. A maioria das APIs modernas não exige que o desenvolvedor propague o CSPRNG para obter segurança.
    
-   Evite funções criptográficas e esquemas de preenchimento obsoletos, como MD5, SHA1, PKCS número 1 v1.5.
    
-   Verifique de forma independente a eficácia das configurações.
    

## Exemplos de Cenários de Ataque

**Cenário #1**: Um aplicativo criptografa números de cartão de crédito em um banco de dados usando criptografia automática de banco de dados. No entanto, esses dados são automaticamente descriptografados quando recuperados, permitindo que uma falha de injeção de SQL recupere números de cartão de crédito em texto não criptografado.

**Cenário #2**: Um site não usa ou impõe TLS para todas as páginas ou oferece suporte a criptografia fraca. Um invasor monitora o tráfego de rede (por exemplo, em uma rede sem fio insegura), faz o downgrade de conexões de HTTPS para HTTP, intercepta solicitações e rouba o cookie de sessão do usuário. O invasor então reproduz esse cookie e sequestra a sessão (autenticada) do usuário, acessando ou modificando os dados privados do usuário. Em vez do acima, eles podem alterar todos os dados transportados, por exemplo, o destinatário de uma transferência de dinheiro.

**Cenário #3**: O banco de dados de senha usa hashes sem saltos ou simples para armazenar as senhas de todos. Uma falha de  _upload_  de arquivo permite que um invasor recupere o banco de dados de senhas. Todos os hashes sem saltos podem ser expostos com uma  _rainbow table_  de hashes pré-calculados. Hashes geradas por funções de hash simples ou rápidas podem ser quebrados por GPUs, mesmo se forem saltadas.

## Referências

-   [OWASP Proactive Controls: Protect Data Everywhere](https://owasp.org/www-project-proactive-controls/v3/en/c8-protect-data-everywhere)
    
-   [OWASP Application Security Verification Standard (V7, 9, 10)](https://owasp.org/www-project-application-security-verification-standard)
    
-   [OWASP Cheat Sheet: Transport Layer Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
    
-   [OWASP Cheat Sheet: User Privacy Protection](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)
    
-   [OWASP Cheat Sheet: Password and Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
    
-   [OWASP Cheat Sheet: HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)
    
-   [OWASP Testing Guide: Testing for weak cryptography](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README)
    

## Lista dos CWEs Mapeados

[CWE-261 Weak Encoding for Password](https://cwe.mitre.org/data/definitions/261.html)

[CWE-296 Improper Following of a Certificate's Chain of Trust](https://cwe.mitre.org/data/definitions/296.html)

[CWE-310 Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html)

[CWE-319 Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

[CWE-321 Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)

[CWE-322 Key Exchange without Entity Authentication](https://cwe.mitre.org/data/definitions/322.html)

[CWE-323 Reusing a Nonce, Key Pair in Encryption](https://cwe.mitre.org/data/definitions/323.html)

[CWE-324 Use of a Key Past its Expiration Date](https://cwe.mitre.org/data/definitions/324.html)

[CWE-325 Missing Required Cryptographic Step](https://cwe.mitre.org/data/definitions/325.html)

[CWE-326 Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

[CWE-327 Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

[CWE-328 Reversible One-Way Hash](https://cwe.mitre.org/data/definitions/328.html)

[CWE-329 Not Using a Random IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html)

[CWE-330 Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)

[CWE-331 Insufficient Entropy](https://cwe.mitre.org/data/definitions/331.html)

[CWE-335 Incorrect Usage of Seeds in Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/335.html)

[CWE-336 Same Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/336.html)

[CWE-337 Predictable Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/337.html)

[CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/338.html)

[CWE-340 Generation of Predictable Numbers or Identifiers](https://cwe.mitre.org/data/definitions/340.html)

[CWE-347 Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)

[CWE-523 Unprotected Transport of Credentials](https://cwe.mitre.org/data/definitions/523.html)

[CWE-720 OWASP Top Ten 2007 Category A9 - Insecure Communications](https://cwe.mitre.org/data/definitions/720.html)

[CWE-757 Selection of Less-Secure Algorithm During Negotiation('Algorithm Downgrade')](https://cwe.mitre.org/data/definitions/757.html)

[CWE-759 Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html)

[CWE-760 Use of a One-Way Hash with a Predictable Salt](https://cwe.mitre.org/data/definitions/760.html)

[CWE-780 Use of RSA Algorithm without OAEP](https://cwe.mitre.org/data/definitions/780.html)

[CWE-818 Insufficient Transport Layer Protection](https://cwe.mitre.org/data/definitions/818.html)

[CWE-916 Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)

## ChatGPT

#### Q1

> Fale sobre A02 - Cryptographic Failures do OWASP

A categoria **A02 - Cryptographic Failures** da [OWASP Top 10](https://owasp.org/Top10/) refere-se a **falhas na criptografia ou no seu uso incorreto**, que podem levar à **exposição de dados sensíveis**, como senhas, dados bancários, números de cartão de crédito, entre outros.

---

## 🔐 O que são Cryptographic Failures?

Essa categoria substitui a antiga "**A3:2017 - Sensitive Data Exposure**", refletindo um foco maior na **causa raiz** (uso incorreto de criptografia), e não apenas no sintoma (dados vazados).

Criptografia não é só “ativar HTTPS”. Trata-se de proteger dados **em repouso**, **em trânsito** e, quando necessário, **em uso**, com algoritmos seguros, boas práticas de chave e políticas adequadas.

---

## ⚠️ Exemplos comuns de falhas

* Transmitir dados sensíveis sem HTTPS (em texto claro).
* Usar algoritmos criptográficos inseguros, como **MD5**, **SHA-1** ou **DES**.
* Gerenciar mal as chaves (armazenadas em código, sem rotação, sem proteção adequada).
* Não criptografar dados sensíveis armazenados, como CPF, cartão, senhas (sem `bcrypt`, `argon2`, `scrypt`, etc.).
* Usar cifras simétricas com **chaves fracas** ou **modos de operação inseguros** (ex: ECB).
* Erros em protocolos de handshake ou autenticação mútua.

---

## 🛡️ Como se proteger

* **Use HTTPS** sempre, com **TLS 1.2 ou superior**.
* **Evite algoritmos obsoletos** — prefira AES, SHA-256, RSA com tamanhos de chave adequados.
* **Armazene senhas com hash seguro**, como:

  * `bcrypt`
  * `argon2`
  * `scrypt`
* **Nunca implemente seu próprio algoritmo criptográfico.**
* Proteja **as chaves**: armazene-as em cofres seguros (como Azure Key Vault, AWS KMS, HashiCorp Vault).
* Faça **rotação de chaves** regularmente.
* Classifique dados sensíveis e só criptografe quando for realmente necessário (evite criptografia superficial).

---

## 📋 Exemplo prático de falha

```plaintext
Sistema armazena senhas dos usuários em texto puro no banco de dados.
Um atacante obtém acesso ao banco (via SQL Injection ou vazamento) e tem todas as senhas.
```

Melhoria:

```php
// Em PHP
$passwordHash = password_hash($password, PASSWORD_BCRYPT);
```

---

## 📎 Referência

* [OWASP Top 10: A02 - Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)

---

Deseja exemplos de código com criptografia correta em alguma linguagem específica, como PHP, Python ou Go?


### Q2

>  Desejo em php

Ótimo! Aqui vão exemplos práticos de **criptografia segura em PHP**, cobrindo os principais cenários:

---

## 🔒 1. **Armazenar senhas com segurança**

Nunca use `md5()` ou `sha1()`! Use `password_hash()` e `password_verify()`:

```php
// Cadastro de usuário
$password = 'minhaSenhaSecreta';
$hash = password_hash($password, PASSWORD_BCRYPT); // ou PASSWORD_ARGON2ID

// Armazenar $hash no banco de dados

// Login
$input = 'minhaSenhaSecreta';
if (password_verify($input, $hash)) {
    echo "Senha correta!";
} else {
    echo "Senha incorreta!";
}
```

---

## 🧾 2. **Criptografar dados sensíveis (AES-256-GCM)**

Para dados que precisam ser descriptografados depois (ex: número de cartão), use criptografia simétrica com **libsodium** (PHP 7.2+).

```php
// Gerar chave segura (guarde com segurança!)
$key = sodium_crypto_secretbox_keygen();

// Criptografar
$nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
$cipher = sodium_crypto_secretbox("texto secreto", $nonce, $key);

// Armazenar $nonce e $cipher no banco

// Descriptografar
$original = sodium_crypto_secretbox_open($cipher, $nonce, $key);
```

> ⚠️ **Nunca reusar o mesmo `nonce` com a mesma `key`!**

---

## 📦 3. **Exemplo com OpenSSL (menos recomendado que libsodium)**

Se precisar usar `openssl_encrypt`, faça assim:

```php
$data = 'Texto sensível';
$key = openssl_random_pseudo_bytes(32); // 256 bits
$iv = openssl_random_pseudo_bytes(16);  // 128 bits

$cipher = openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv);

// Armazenar $cipher e $iv com segurança

// Descriptografar
$original = openssl_decrypt($cipher, 'aes-256-cbc', $key, 0, $iv);
```

> ⚠️ Evite `aes-256-ecb`! O modo ECB **não é seguro**, pois revela padrões nos dados.

---

## 🛑 O que evitar

| Inseguro          | Motivo                   | Substitua por                     |
| ----------------- | ------------------------ | --------------------------------- |
| `md5()`           | Quebrado e rápido        | `password_hash()`                 |
| `sha1()`          | Vulnerável a colisões    | `password_hash()` ou SHA-256      |
| `base64_encode()` | Não é criptografia!      | Use `sodium_crypto_*`             |
| `aes-256-ecb`     | Revela padrões nos dados | Use `aes-256-gcm` ou `cbc` com IV |

---

Quer que eu monte um exemplo completo (formulário de cadastro + login + criptografia de dados sensíveis) em PHP puro ou Laravel?

### Q3

> Fale mais e uso incrreto ou nao uso de criptografia quando se deveria usar

Claro, Rafael! O **uso incorreto ou a ausência de criptografia quando necessária** é uma das **principais causas** de vulnerabilidades do tipo **A02 - Cryptographic Failures** segundo o OWASP. Isso não significa apenas escolher um algoritmo ruim, mas também **negligenciar totalmente a criptografia** em momentos críticos. Vamos explorar isso em profundidade:

---

## ⚠️ **Exemplos de ausência ou uso incorreto de criptografia**

### 1. **Transmissão de dados sem HTTPS**

Enviar dados via HTTP (sem TLS) significa que **qualquer um na rede pode interceptar os dados** com ferramentas simples como Wireshark.

**Errado:**

```html
<form action="http://example.com/login" method="post">
```

**Correto:**

```html
<form action="https://example.com/login" method="post">
```

**Consequência:** senhas, tokens e informações sensíveis são enviados em **texto puro** pela rede.

---

### 2. **Armazenar senhas em texto puro ou hash inseguro**

**Errado:**

```php
$hash = md5($senha); // Muito rápido e já quebrado
```

**Correto:**

```php
$hash = password_hash($senha, PASSWORD_ARGON2ID);
```

**Consequência:** Se o banco for vazado, o atacante pode recuperar facilmente as senhas (com dicionários ou rainbow tables).

---

### 3. **Dados sensíveis no banco sem criptografia**

Imagine que você armazene CPF, RG, cartão de crédito ou dados médicos no banco **sem criptografia**. Se o banco for exposto por qualquer motivo (SQL Injection, acesso indevido, backup perdido), os dados estarão legíveis.

**Solução:** criptografar com AES (libsodium) ou criptografia de campo (ex: Laravel Encryption, Doctrine Encrypted types, etc).

---

### 4. **Armazenar chaves criptográficas em código-fonte**

**Errado:**

```php
$key = 'minha-chave-muito-secreta'; // hardcoded
```

**Correto:**

```php
$key = getenv('APP_KEY'); // ou vindo de um cofre seguro
```

**Consequência:** se alguém acessar o repositório ou deploy, consegue descriptografar todos os dados.

---

### 5. **Usar algoritmos quebrados ou modos errados**

**Errado:**

```php
openssl_encrypt($dados, 'aes-256-ecb', $key);
```

* Modo ECB é determinístico — **padrões nos dados se repetem** no ciphertext.

**Correto:**

```php
openssl_encrypt($dados, 'aes-256-cbc', $key, 0, $iv); // ou AES-GCM
```

---

### 6. **Falta de criptografia em backups**

Mesmo que os dados estejam criptografados em produção, se os **backups estiverem em texto claro**, todo o esforço é perdido.

---

### 7. **Sem autenticação de integridade**

Você criptografa dados, mas não verifica se **foram alterados**. Um atacante pode modificar o ciphertext e causar problemas no sistema (ataques tipo padding oracle, por exemplo).

**Solução:** use **criptografia autenticada**, como **AES-GCM** ou libsodium, que já fazem isso automaticamente.

---

## ✅ Quando você deve usar criptografia?

| Situação                         | Exemplo                                | Proteção Recomendada                    |
| -------------------------------- | -------------------------------------- | --------------------------------------- |
| Autenticação                     | Senhas, tokens de sessão               | `password_hash`, TLS                    |
| Armazenamento de dados sensíveis | CPF, RG, cartão, dados médicos         | AES-256-GCM ou libsodium                |
| Transmissão de dados             | API, login, formulários                | HTTPS / TLS                             |
| Dados em cache                   | Dados temporários sensíveis            | Criptografia em cache                   |
| Backups                          | Dumps de banco com dados sensíveis     | Criptografia e controle de acesso       |
| Dados em cookies                 | Informações de sessão, identificadores | Cookies seguros + `HttpOnly` + `Secure` |

---

Se quiser, posso revisar algum trecho de um código seu em PHP para ver se há falhas criptográficas ou sugerir melhorias. Deseja isso?


## Perplexity

<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" class="logo" width="120"/>

# A02:2021 - Falhas Criptográficas: Compreensão, Riscos e Medidas de Prevenção

A categoria A02:2021 - Falhas Criptográficas representa a segunda vulnerabilidade mais crítica na lista OWASP Top 10 de 2021. Anteriormente conhecida como "Sensitive Data Exposure" (Exposição de Dados Sensíveis), esta categoria foi renomeada para enfatizar as causas raiz das vulnerabilidades em vez de seus sintomas. As falhas criptográficas ocorrem quando dados sensíveis não são adequadamente protegidos devido a deficiências em algoritmos de criptografia, gerenciamento de chaves, métodos de transmissão e outras práticas criptográficas, podendo resultar em exposição de informações críticas e comprometimento de sistemas inteiros.

## Compreendendo as Falhas Criptográficas

As falhas criptográficas referem-se a vulnerabilidades que surgem da implementação inadequada ou uso impróprio de sistemas criptográficos, levando à exposição de dados sensíveis ou ao comprometimento de sistemas. Esta categoria exige atenção especial para a proteção de dados como senhas, números de cartões de crédito, registros de saúde, informações pessoais e segredos empresariais, especialmente quando essas informações são protegidas por regulamentos como o GDPR ou o PCI DSS[^18].

### Causas Principais

Uma das causas mais comuns de falhas criptográficas é o uso de algoritmos criptográficos fracos ou obsoletos. Por exemplo, funções hash como MD5 são conhecidas por serem vulneráveis a ataques, mas continuam sendo usadas em muitos sistemas[^19]. Algoritmos criptográficos que eram considerados seguros no passado podem se tornar vulneráveis com o avanço da tecnologia e do poder computacional.

O gerenciamento inadequado de chaves criptográficas representa outro problema crítico. Isso inclui armazenamento inseguro, geração fraca e manuseio inadequado das chaves utilizadas nos processos de criptografia[^19]. Quando as chaves são mal protegidas, mesmo o algoritmo mais robusto pode ser comprometido.

A transmissão de dados sensíveis através de canais não criptografados ou inseguros é outra falha comum. Sem a devida proteção durante a transmissão, os dados ficam vulneráveis à interceptação e acesso não autorizado[^17].

### Consequências das Falhas Criptográficas

As falhas criptográficas podem ter consequências devastadoras. Um exemplo notável mencionado nos resultados de pesquisa é a violação de dados do Freecycle, onde o uso de algoritmos criptográficos fracos levou a uma grave exposição de informações[^19]. Quando dados sensíveis são comprometidos, as organizações podem enfrentar danos financeiros, legais e reputacionais significativos.

## Prevenção de Falhas Criptográficas

### Melhores Práticas e Estratégias

Para prevenir falhas criptográficas, a OWASP recomenda a implementação de protocolos de criptografia fortes e atualizados. É fundamental utilizar algoritmos que sejam resistentes a ataques modernos e que tenham passado por rigorosa revisão pela comunidade de segurança[^19].

O gerenciamento adequado de chaves criptográficas é essencial. Isso inclui práticas como rotação regular de chaves, armazenamento seguro e controles de acesso rigorosos para limitar quem pode utilizar as chaves[^17].

A criptografia deve ser aplicada tanto para dados em trânsito quanto para dados em repouso. Informações sensíveis não devem ser transmitidas em texto simples, e conexões seguras como HTTPS devem ser implementadas consistentemente[^18].

### Recursos e Ferramentas

A OWASP oferece várias folhas de referência (cheat sheets) relacionadas à prevenção de falhas criptográficas:

- Cryptographic Storage Cheat Sheet
- Transport Layer Security Cheat Sheet
- HTTP Strict Transport Security Cheat Sheet
- Secrets Management Cheat Sheet
- Key Management Cheat Sheet
- Pinning Cheat Sheet[^17]

Essas folhas de referência fornecem orientações detalhadas sobre como implementar corretamente práticas criptográficas seguras em diferentes contextos.

### Ferramentas de Detecção e Mitigação

Diversas ferramentas podem ajudar a identificar e mitigar vulnerabilidades criptográficas:

Ferramentas de código aberto:

- SAST (Análise Estática de Código): Bandit para Python
- DAST (Análise Dinâmica de Segurança): Zap
- Detecção de Segredos: GitLeaks
- SCA (Análise de Composição de Software): Trivy[^19]

Estas ferramentas podem ser integradas a pipelines de CI/CD para identificar proativamente problemas criptográficos antes que eles se tornem vulnerabilidades exploráveis.

## Caso de Estudo: A Violação de Dados do Freecycle

Um exemplo importante mencionado nos resultados da pesquisa é a violação de dados do Freecycle. Este caso ilustra as consequências devastadoras do uso de algoritmos criptográficos fracos. A violação resultou na exposição de dados sensíveis dos usuários, destacando a importância de implementar práticas criptográficas robustas desde o início do desenvolvimento de aplicações[^19].

### Lições Aprendidas

O caso Freecycle enfatiza a necessidade de:

- Avaliar regularmente a força dos algoritmos criptográficos utilizados
- Atualizar sistemas para implementar algoritmos mais seguros
- Considerar a criptografia como um componente essencial do design de segurança, não como um adicional


## Aspectos Técnicos das Falhas Criptográficas

### Algoritmos Criptográficos Comumente Vulneráveis

Certos algoritmos criptográficos são conhecidamente vulneráveis e devem ser evitados:

- MD5 e SHA-1 para funções hash
- DES e 3DES para criptografia simétrica
- RSA com chaves curtas para criptografia assimétrica[^17]


### Implementação Correta de Protocolos Criptográficos

A implementação correta de protocolos criptográficos deve considerar:

- Uso apropriado de vetores de inicialização (IVs)
- Implementação de sal (salt) para hashing de senhas
- Seleção de modos de operação seguros para algoritmos de blocos criptográficos
- Validação adequada de certificados[^17][^19]


## Conclusão

As falhas criptográficas representam um risco significativo para aplicações web modernas, ocupando a segunda posição na lista OWASP Top 10 de 2021. A proteção adequada de dados sensíveis requer uma abordagem abrangente que inclua a seleção cuidadosa de algoritmos criptográficos, gerenciamento apropriado de chaves, proteção de dados em trânsito e em repouso, e aplicação consistente de melhores práticas de segurança.

As organizações devem considerar a criptografia como um componente fundamental de sua estratégia de segurança, não como um adicional. Implementar as recomendações da OWASP e utilizar as ferramentas disponíveis para detecção e mitigação de vulnerabilidades pode ajudar significativamente a reduzir o risco associado às falhas criptográficas.

À medida que as ameaças evoluem e as técnicas de ataque se tornam mais sofisticadas, manter-se atualizado sobre as melhores práticas criptográficas e revisar regularmente implementações existentes torna-se cada vez mais importante para garantir a segurança contínua dos dados e sistemas.

<div style="text-align: center">⁂</div>

[^1]: https://www.gratitech.com/blog/overview-of-owasp-top-10-v2021-a02-cryptographic-failures

[^2]: https://www.indusface.com/blog/owasp-top-10-vulnerabilities-in-2021-how-to-mitigate-them/

[^3]: https://medium.com/traceable-and-true/owasp-a02-cryptographic-failures-what-they-are-and-why-they-are-important-69bac793bc1e

[^4]: https://niccs.cisa.gov/education-training/catalog/cybrary/owasp-top-10-a022021-cryptographic-failures

[^5]: https://github.com/OWASP/CheatSheetSeries/blob/master/IndexTopTen.md

[^6]: https://wisewordsworth.com/cryptographic-failures-causes-cases-prevention/

[^7]: https://securityboulevard.com/2023/09/item-recycling-site-freecycle-is-hit-with-a-massive-data-breach/

[^8]: https://cheatsheetseries.owasp.org/IndexTopTen.html

[^9]: https://cirl.io/unveiling-a022021-cryptographic-failures/

[^10]: https://owasp.org/Top10/A02_2021-Cryptographic_Failures/

[^11]: https://owasp.org/Top10/A02_2021-Cryptographic_Failures/

[^12]: https://owaspsecure.com/learn/vuln2.html

[^13]: https://github.com/OWASP/Top10/blob/master/2021/docs/A02_2021-Cryptographic_Failures.md

[^14]: https://github.com/OWASP/Top10/blob/master/2021/docs/A02_2021-Cryptographic_Failures.md

[^15]: https://www.youtube.com/watch?v=nM_qPfbOitU

[^16]: https://cheatsheetseries.owasp.org/IndexTopTen.html

[^17]: https://bugxhunter.com/owasp-top-ten-a022021-cryptographic-failures/

[^18]: https://www.myrasecurity.com/en/knowledge-hub/owasp-top-10/

[^19]: https://www.youtube.com/watch?v=cftWboGdETE

[^20]: https://www.feroot.com/blog/owasp-top-10-whats-new-in-the-2021-release/

[^21]: https://www.zerolynx.com/en/blogs/news/cryptographic

[^22]: https://apicontext.com/blog-owasp-2-cryptographic-failures-what-they-are-why-they-are-important-and-how-to-prevent-them/

[^23]: https://outpost24.com/blog/owasp-top-10-2021-what-is-new/

[^24]: https://www.youtube.com/watch?v=85Ds9wOPESw

[^25]: https://www.pullrequest.com/blog/what-are-cryptographic-failures-and-how-to-prevent-giant-leaks/

[^26]: https://owasp.org/Top10/

[^27]: https://www.linkedin.com/pulse/understanding-a022021-cryptographic-failures-owasp-top-iyltc

[^28]: https://niccs.cisa.gov/education-training/catalog/cybrary/owasp-top-10-a022021-cryptographic-failures

[^29]: https://niccs.cisa.gov/education-training/catalog/skillsoft/owasp-top-10-a022021-cryptographic-failures

[^30]: https://www.youtube.com/watch?v=Uzvj4OyG0dE

[^31]: https://owasp.org/Top10/A02_2021-Cryptographic_Failures/

[^32]: https://www.youtube.com/watch?v=kdTkj6DdbCg

[^33]: https://blog.checkpoint.com/security/great-crypto-failures-when-malware-goes-wrong/

[^34]: https://heimdalsecurity.com/blog/freecycle-confirms-data-breach-affecting-over-7-million-users/

[^35]: https://gbhackers.com/owasp-top-10-2021/

[^36]: https://www.pynt.io/learning-hub/owasp-top-10-guide/owasp-top-10-cheat-sheet-threats-and-mitigations-in-brief

[^37]: https://teamwin.in/index.php/2025/01/10/what-is-cryptographic-failures/

[^38]: https://www.grcreport.com/post/freecycle-confirms-data-breach-impacting-over-7-million-users

[^39]: https://owasp.org/www-project-developer-guide/draft/foundations/owasp_top_ten/

[^40]: https://github.com/3ls3if/Cybersecurity-Notes/blob/main/readme/owasp-top-10/web/a02-2021-cryptographic-failures.md

[^41]: https://cybersecuritynews.com/freecycle-data-breach/

