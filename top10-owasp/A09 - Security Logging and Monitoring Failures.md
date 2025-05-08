# A09:2021 - Security Logging and Monitoring Failures

## Resumo

Falta (ou falha) de log de segurnaça para monitorar (ou seja detectar) e até mesmo alertar em real-time ataques.

> É quando uma aplicação não registra eventos críticos, não monitora acessos ou ações sensíveis, ou não alerta administradores sobre atividades suspeitas. Isso dificulta detectar violações de segurança, identificar responsáveis e realizar auditorias.

## Links

+ OWASP Oficial Eng
   	+ <https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/>
+ Owap Oficial - PT-BR
    + <https://owasp.org/Top10/pt_BR/A09_2021-Security_Logging_and_Monitoring_Failures/>

## Minhas observações

+ Em situações críticas (como login) deve-se salvar log semrpe que der certo e também se der falha. Se a pessoa tenta acessar um recurso e ela não tem usuário ou nâo tem perfil admin, deve-se salvar o log pois pode ser o início de uma tentativa de aaque. Salvar: IP e user-agent,  time-stamp

## Exemplos de situações que caracterizam essa falha

### ChatGPT

+ Falta de **logs de autenticação** (logins bem-sucedidos e falhos).
+ Logs que **não armazenam dados suficientes** para uma análise forense (ex: IP, user-agent, timestamp).
+ Ausência de **alertas para tentativas de acesso indevido** ou mudanças críticas (como alteração de senha ou permissões).
+ Logs **acessíveis publicamente** ou **armazenados sem segurança**.
+ Monitoramento e alertas **não configurados** ou **ineficientes**.

### OWASP

A falta de registro, detecção, monitoramento e resposta ativa ocorre sempre que:

+ Eventos auditáveis, como logins, logins falhos e transações de alto valor, não são registrados.
+ Avisos e erros geram mensagens de log inexistentes, inadequadas ou confusas.
+ Logs de aplicativos e APIs não são monitorados quanto a atividades suspeitas.
+ Logs são armazenados apenas localmente.
+ Limiares de alerta apropriados e processos de escalonamento de resposta não estão em vigor ou são eficazes.
+ Testes de penetração e varreduras por ferramentas de teste de segurança de aplicativos dinâmicos (DAST), como OWASP ZAP, não acionam alertas.
+ A aplicação não pode detectar, escalonar ou alertar para ataques ativos em tempo real ou quase em tempo real.

## Riscos que isso causa

+ **Detecção tardia** de invasões e ataques.
+ **Impossibilidade de investigar incidentes** de segurança com precisão.
+ **Perda de conformidade** com normas e leis (como LGPD, GDPR, PCI-DSS).
+ Maior impacto de um ataque por **falta de resposta rápida**

## Como Prevenir

### Como Prevenir - ChatGPT

1. **Registrar eventos importantes**, como:
    + Autenticações (sucesso e falha);
    + Alterações de configuração e permissões;
    + Acesso a dados sensíveis.

2. **Proteger os logs**:
    + Criptografia e acesso restrito;
    + Integridade dos registros.

3. **Configurar alertas automáticos**:
    + Para múltiplas tentativas de login;
    + Para ações administrativas.

4. **Centralizar e monitorar logs** com ferramentas como:
    + ELK Stack (Elasticsearch, Logstash, Kibana),
    + Splunk,
    + Graylog
    + Azure Monitor ou AWS CloudWatch.

5. **Testar e revisar periodicamente** as estratégias de logging e monitoramento.

### Owasp

Os desenvolvedores devem implementar alguns ou todos os controles a seguir, dependendo do risco da aplicação:

+ Garantir que todas as falhas de login, controle de acesso e validação de entrada no lado do servidor possam ser registradas com contexto de usuário suficiente para identificar contas suspeitas ou maliciosas e mantidas por tempo suficiente para permitir análise forense atrasada.
+ Garantir que os logs sejam gerados em um formato que as soluções de gerenciamento de logs possam facilmente consumir.
+ Garantir que os dados de log sejam codificados corretamente para evitar injeções ou ataques nos sistemas de registro ou monitoramento.
+ Garantir que transações de alto valor tenham uma trilha de auditoria com controles de integridade para evitar adulteração ou exclusão, como tabelas de banco de dados somente para adição ou similares.
+ As equipes de DevSecOps devem estabelecer monitoramento e alerta efetivos para que atividades suspeitas sejam detectadas e respondidas rapidamente.
+ Estabelecer ou adotar um plano de resposta e recuperação de incidentes, como o National Institute of Standards and Technology (NIST) 800-61r2 ou posterior.

Existem estruturas de proteção de aplicativos comerciais e de código aberto, como o OWASP ModSecurity Core Rule Set, e software de correlação de logs de código aberto, como o Elasticsearch, Logstash, Kibana (ELK) stack, que possuem painéis personalizados e alertas.

## Exemplos de Cenários de Ataque

Cenário 1: O operador do site do provedor de plano de saúde infantil não conseguiu detectar uma violação devido à falta de monitoramento e registro. Uma parte externa informou ao provedor do plano de saúde que um invasor havia acessado e modificado milhares de registros de saúde sensíveis de mais de 3,5 milhões de crianças. Uma revisão pós-incidente descobriu que os desenvolvedores do site não haviam abordado vulnerabilidades significativas. Como não houve registro ou monitoramento do sistema, a violação de dados pode ter estado em andamento desde 2013, um período de mais de sete anos.

Cenário 2: Uma grande companhia aérea indiana teve uma violação de dados envolvendo dados pessoais de milhões de passageiros por mais de dez anos, incluindo dados de passaporte e cartão de crédito. A violação de dados ocorreu em um provedor de hospedagem em nuvem de terceiros, que notificou a companhia aérea da violação depois de algum tempo.

Cenário nº 3: Uma grande companhia aérea europeia sofreu uma violação relatável do GDPR. A violação foi supostamente causada por vulnerabilidades de segurança do aplicativo de pagamento exploradas por invasores, que colheram mais de 400.000 registros de pagamento de clientes. A companhia aérea foi multada em 20 milhões de libras como resultado pelo regulador de privacidade.

## Conversa com ChatGPT

### chatgpt 1 - Que dados de log devo armazenar no php puro

> Que dados devo armazenar para fazer uma análise forence, dê um exemplo em php puro

Para uma **análise forense eficaz** após um incidente de segurança, você precisa armazenar dados que permitam **rastrear ações suspeitas, identificar o responsável e entender o impacto do ataque**.

---

📋 Dados recomendados para registrar (mínimo):

1. **Timestamp** (data e hora exata do evento)
2. **IP do usuário**
3. **User-Agent** (navegador, sistema operacional, etc.)
4. **Tipo de ação** (ex: login, acesso a dado sensível, falha de autenticação)
5. **Identificador do usuário** (ex: ID, email, login)
6. **Recurso acessado** (rota, endpoint, página, etc.)
7. **Resultado da ação** (sucesso, erro, falha de autenticação)
8. **Dados relevantes da requisição** (se possível, sem incluir informações sensíveis como senhas)

---

🧪 Exemplo prático em **PHP puro**:

```php
<?php
function registrarEventoSeguranca($tipoAcao, $usuarioId = null, $resultado = null) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'IP desconhecido';
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'User-Agent desconhecido';
    $uri = $_SERVER['REQUEST_URI'] ?? 'Recurso desconhecido';
    $timestamp = date('Y-m-d H:i:s');
    
    $log = [
        'timestamp' => $timestamp,
        'ip' => $ip,
        'user_agent' => $userAgent,
        'usuario_id' => $usuarioId,
        'acao' => $tipoAcao,
        'recurso' => $uri,
        'resultado' => $resultado
    ];

    $linha = json_encode($log) . PHP_EOL;
    file_put_contents(__DIR__ . '/logs/seguranca.log', $linha, FILE_APPEND);
}

// Exemplo de uso:
registrarEventoSeguranca('tentativa_login', 'rafael.morais', 'falha');
```

---

📌 Dicas adicionais:

+ Use um **arquivo separado para logs de segurança** (ex: `seguranca.log`).
+ **Evite registrar dados sensíveis** diretamente (como senhas ou tokens).
+ Proteja o diretório de logs contra acesso externo via `.htaccess` ou configuração do servidor.
+ Considere enviar logs críticos para um servidor remoto ou ferramenta centralizada (ELK, Graylog, etc.).

---

Quer que eu adapte isso para gravar os dados em um banco de dados ou para registrar ações específicas como uploads, alterações de senha ou deletações?

### chatgpt 2 - como fazer no laravel

No **Laravel**, é ainda mais simples e robusto registrar eventos de segurança, pois o framework já oferece suporte integrado ao sistema de logs via o **Log facade** e configurações centralizadas no `config/logging.php`.

---

✅ Exemplo prático: Registrar evento de segurança no log padrão

```php
use Illuminate\Support\Facades\Log;

public function login(Request $request)
{
    $usuario = $request->input('user'); // ou auth()->user()->id;
    $ip = $request->ip();
    $userAgent = $request->userAgent();
    $rota = $request->path();
    $dataHora = now()->toDateTimeString();

    Log::channel('security')->info('Tentativa de login', [
        'timestamp' => $dataHora,
        'ip' => $ip,
        'user_agent' => $userAgent,
        'usuario' => $usuario,
        'rota' => $rota,
        'resultado' => 'falha',
    ]);

    // continue com o login...
}
```

---

🛠 Como configurar um canal de log específico para segurança

1. **Abra o arquivo `config/logging.php`**
2. **Adicione um novo canal** em `'channels'`:

```php
'channels' => [
    // ... outros canais
    'security' => [
        'driver' => 'single',
        'path' => storage_path('logs/security.log'),
        'level' => 'info',
    ],
],
```

Isso criará um arquivo em `storage/logs/security.log`.

---

📈 Resultado no log (`security.log`)

```json
[2025-05-03 15:02:11] local.INFO: Tentativa de login {"timestamp":"2025-05-03 15:02:11","ip":"192.168.0.1","user_agent":"Mozilla/5.0","usuario":"rafael.morais","rota":"login","resultado":"falha"}
```

---

🧠 Boas práticas

+ Use **nível `warning` ou `alert`** para eventos suspeitos (ex: muitas tentativas de login).
+ **Criptografe ou filtre dados sensíveis** antes de registrar.
+ **Centralize os logs** com serviços como ELK Stack, Sentry, Papertrail, etc. (Laravel suporta via drivers).

---

Quer um exemplo para registrar eventos de alteração de senha, download de arquivos ou acesso a dados confidenciais?

## Referências do OWASP

+ [OWASP Proactive Controls: Implement Logging and Monitoring](https://owasp.org/www-project-proactive-controls/v3/en/c9-security-logging.html)

+ [OWASP Application Security Verification Standard: V7 Logging and Monitoring](https://owasp.org/www-project-application-security-verification-standard)

+ [OWASP Testing Guide: Testing for Detailed Error Code](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_for_Error_Code)

+ [OWASP Cheat Sheet: Application Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html)

+ [OWASP Cheat Sheet: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

+ [Data Integrity: Recovering from Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-11/final)

+ [Data Integrity: Identifying and Protecting Assets Against Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-25/final)

+ [Data Integrity: Detecting and Responding to Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-26/final)

**CVW**

[CWE-117 Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)

[CWE-223 Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)

[CWE-532 Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)

[CWE-778 Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
