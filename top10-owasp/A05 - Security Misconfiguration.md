# A05 - Security Misconfiguration

## Resumo

Sâoq uesôes de configuraçoes default, ou sem restrçao ouq ue msotrma demais (como explodir o stack trace); CORS, Servidor, Permisses e Headers mal configurados; Coisa de desenvolvimento e produçao; ativado o ambient de debug em produçao

## Links

+ https://owasp.org/Top10/pt_BR/A05_2021-Security_Misconfiguration/

--==========================================================
--==========================================================
--==========================================================
--==========================================================
--==========================================================

## OWASP

## Descrição

A aplicação pode ser vulnerável se for:

+ Falta de proteção de segurança apropriada em qualquer parte da  _stack_  das aplicações ou permissões configuradas incorretamente em serviços em nuvem.

+ Recursos desnecessários são ativados ou instalados (por exemplo, portas, serviços, páginas, contas ou privilégios desnecessários).

+ As contas padrão e suas senhas ainda estão ativadas e inalteradas.

+ O tratamento de erros revela  _stack traces_  ou outras mensagens de erro excessivamente informativas aos usuários.

+ Para sistemas atualizados, os recursos de segurança mais recentes estão desabilitados ou não estão configurados com segurança.

+ As configurações de segurança nos servidores das aplicações, nos  _frameworks_  (por exemplo, Struts, Spring, ASP.NET), bibliotecas, bancos de dados, etc., não estão definidas para proteger os valores.

+ O servidor não envia cabeçalhos ou diretivas de segurança, ou eles não estão configurados para proteger os valores.

+ O software está desatualizado ou vulnerável (consulte  [A06: 2021-Componentes Vulneráveis e Desatualizados](https://owasp.org/Top10/pt_BR/A06_2021-Vulnerable_and_Outdated_Components/)).

Sem um processo de configuração de segurança de aplicações que seja integrado e repetível, os sistemas correm um risco maior.

## Como Prevenir

Devem ser implementados processos de instalação segura, incluindo:

+ Um processo de proteção repetível torna mais rápido e fácil implantar outro ambiente que esteja devidamente bloqueado. Os ambientes de desenvolvimento, controle de qualidade e produção devem ser todos configurados de forma idêntica, com credenciais diferentes usadas em cada ambiente. Este processo deve ser automatizado para minimizar o esforço necessário para configurar um novo ambiente seguro.

+ Uma plataforma mínima sem recursos, componentes, documentação e outros desnecessários. Remova ou não instale recursos e estruturas não utilizados.

    + Uma tarefa para revisar e atualizar as configurações apropriadas para todas as notas de segurança, atualizações e patches como parte do processo de gerenciamento de patch (consulte  [A06: 2021-Componentes Vulneráveis e Desatualizados](https://owasp.org/Top10/pt_BR/A06_2021-Vulnerable_and_Outdated_Components/)). Revise as permissões de armazenamento em nuvem (por exemplo,  _S3 bucket permissions_).

+ Uma arquitetura de aplicação segmentada fornece separação eficaz e segura entre componentes ou  _tenants_, com segmentação, conteinerização ou grupos de segurança em nuvem (ACLs).

+ Envio de diretivas de segurança para clientes, por exemplo,  _Security Headers_.

+ Um processo automatizado para verificar a eficácia das configurações em todos os ambientes.

## Exemplos de Cenários de Ataque

**Cenário #1:**  O servidor da aplicação é fornecido com os sistemas de amostra não removidos do servidor de produção. Esses aplicativos de amostra têm falhas de segurança conhecidas que os invasores usam para comprometer o servidor. Suponha que um desses aplicativos seja o console de administração e as contas padrão não tenham sido alteradas. Nesse caso, o invasor efetua login com as senhas padrão e assume o controle.

**Cenário #2:**  A listagem do diretório não está desabilitada no servidor. Um invasor descobre que pode simplesmente listar diretórios. O invasor encontra e baixa as classes Java compiladas, que ele descompila e faz engenharia reversa para visualizar o código. O invasor então encontra uma falha grave de controle de acesso no aplicativo.

**Cenário #3:**  A configuração do servidor de aplicações permite que os detalhes das mensagens de erro, por exemplo,  _stack trace_, sejam retornadas aos usuários. Isso potencialmente expõe informações confidenciais ou falhas subjacentes, como versões de componentes que são conhecidas por serem vulneráveis.

**Cenário #4:**  Um provedor de serviços de nuvem tem permissões de compartilhamento padrão abertas para a Internet por outros usuários de  _Content Security Policy header (CSP)_. Isso permite que dados confidenciais armazenados no armazenamento em nuvem sejam acessados.

## Referências

+ [OWASP Testing Guide: Configuration Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)

+ [OWASP Testing Guide: Testing for Error Codes](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)

+ Application Security Verification Standard V19 Configuration

+ [NIST Guide to General Server Hardening](https://csrc.nist.gov/publications/detail/sp/800-123/final)

+ [CIS Security Configuration Guides/Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

+ [Amazon S3 Bucket Discovery and Enumeration](https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html)

## Lista dos CWEs Mapeados

[CWE-2 7PK - Environment](https://cwe.mitre.org/data/definitions/2.html)

[CWE-11 ASP.NET Misconfiguration: Creating Debug Binary](https://cwe.mitre.org/data/definitions/11.html)

[CWE-13 ASP.NET Misconfiguration: Password in Configuration File](https://cwe.mitre.org/data/definitions/13.html)

[CWE-15 External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html)

[CWE-16 Configuration](https://cwe.mitre.org/data/definitions/16.html)

[CWE-260 Password in Configuration File](https://cwe.mitre.org/data/definitions/260.html)

[CWE-315 Cleartext Storage of Sensitive Information in a Cookie](https://cwe.mitre.org/data/definitions/315.html)

[CWE-520 .NET Misconfiguration: Use of Impersonation](https://cwe.mitre.org/data/definitions/520.html)

[CWE-526 Exposure of Sensitive Information Through Environmental Variables](https://cwe.mitre.org/data/definitions/526.html)

[CWE-537 Java Runtime Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/537.html)

[CWE-541 Inclusion of Sensitive Information in an Include File](https://cwe.mitre.org/data/definitions/541.html)

[CWE-547 Use of Hard-coded, Security-relevant Constants](https://cwe.mitre.org/data/definitions/547.html)

[CWE-611 Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)

[CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html)

[CWE-756 Missing Custom Error Page](https://cwe.mitre.org/data/definitions/756.html)

[CWE-776 Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')](https://cwe.mitre.org/data/definitions/776.html)

[CWE-942 Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html)

[CWE-1004 Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)

[CWE-1032 OWASP Top Ten 2017 Category A6 - Security Misconfiguration](https://cwe.mitre.org/data/definitions/1032.html)

[CWE-1174 ASP.NET Misconfiguration: Improper Model Validation](https://cwe.mitre.org/data/definitions/1174.html)

--==========================================================
--==========================================================
--==========================================================
--==========================================================
--==========================================================
--==========================================================
--==========================================================

## Chatpgt

### Q1 - CHATPGT - O que é A05

> Fale sobre A05 Security Misconfiguration do OWASP

Claro! A **A05:2021 - Security Misconfiguration** (ou **"Configuração de Segurança Incorreta"**) é uma das vulnerabilidades mais comuns e perigosas listadas pelo **OWASP Top 10**, e afeta tanto aplicações simples quanto sistemas corporativos complexos.

---

## 🔐 O que é a A05 - Security Misconfiguration?

É quando uma aplicação, servidor, banco de dados ou serviço **está configurado de forma insegura**, seja por padrão fraco, falta de restrições ou configurações incorretas/omitidas. Isso pode abrir brechas graves para invasores.

---

## ⚠️ Exemplos típicos

| Situação                                                                                 | Impacto                                                      |
| ---------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| Servidor web exibindo mensagens de erro detalhadas                                       | Exposição de stack trace e estruturas internas               |
| Console de administração sem autenticação ou exposto na internet                         | Controle total do sistema                                    |
| CORS mal configurado                                                                     | Permite requisições indevidas de domínios não autorizados    |
| Headers de segurança ausentes (como `X-Content-Type-Options`, `Content-Security-Policy`) | Facilita ataques como XSS, clickjacking                      |
| Permissões excessivas em arquivos ou diretórios                                          | Vazamento ou alteração de arquivos sensíveis                 |
| Ambiente de desenvolvimento ativo em produção                                            | Pode incluir debug aberto, senhas hardcoded, verbose logging |
| Configuração padrão de banco de dados (usuário "root", sem senha)                        | Acesso total não controlado                                  |

---

## 🎯 Como ela se relaciona com **boas práticas de desenvolvimento seguro**

A A05 acontece, em geral, quando:

+ A equipe esquece de revisar as configurações padrão (do servidor, app ou dependência).
+ Há falta de consistência entre **ambientes de dev, staging e produção**.
+ Não há processos de **hardening (reforço de segurança)** e **automatização** de configurações seguras.

---

## 🛡️ Como se proteger

### 1. **Desabilite o que não usa**

+ Remova consoles, endpoints de debug, permissões de arquivos, usuários padrão.

### 2. **Revise as configurações de segurança**

+ Cheque CORS, headers HTTP, autenticação, permissões de acesso.

### 3. **Automatize e padronize**

+ Use ferramentas como **Ansible**, **Terraform**, **Dockerfile hardening** e **CI/CD pipelines** com políticas seguras.

### 4. **Configure o ambiente corretamente**

+ Separe credenciais, desative debug em produção, restrinja portas/serviços, use HTTPS sempre.

### 5. **Use scanners de segurança**

+ Ferramentas como **OWASP ZAP**, **Nikto**, **Nmap**, **SSL Labs**, **Mozilla Observatory** podem detectar falhas de configuração.

---

## 📌 Exemplo prático (Laravel)

### Erro:

`APP_DEBUG=true` no `.env` em produção

### Risco:

Mostra detalhes de exceções, paths, queries e até senhas em erro de conexão.

### Correto:

```env
APP_DEBUG=false
APP_ENV=production
```

---

Se quiser, posso revisar com você algumas configurações de segurança em um projeto Laravel seu, ou mostrar como usar scanners como o ZAP para encontrar essas falhas. Deseja?

### Q2 - Exemplos disos em php e laravel

> De exemplo disos no php puro, e no laravel

Claro, Rafael! Vamos ver **exemplos práticos da A05 - Security Misconfiguration** tanto em **PHP puro** quanto em **Laravel**, para entender como essas falhas aparecem e como evitá-las.

---

## 🔸 PHP PURO — Exemplos de **misconfiguração de segurança**

### ❌ **1. Exibição de erros em produção**

```php
// Em produção
ini_set('display_errors', 1);
error_reporting(E_ALL);
```

➡️ Isso mostra detalhes de falhas ao usuário final, como paths e queries.

✅ **Correção:**

```php
// Em produção
ini_set('display_errors', 0);
error_reporting(0);
// E registrar em log seguro
ini_set('log_errors', 1);
ini_set('error_log', '/var/log/php_errors.log');
```

---

### ❌ **2. Diretório com permissões erradas**

```bash
chmod -R 777 /var/www/html/
```

➡️ Qualquer processo pode modificar arquivos da aplicação. Risco grave!

✅ **Correção:**

```bash
chmod -R 755 /var/www/html/
chown -R www-data:www-data /var/www/html/
```

---

### ❌ **3. Arquivo de configuração exposto**

```bash
# Exemplo: acesso público ao .env, .ini ou config.php
http://example.com/config.php
```

➡️ Permite acesso a senhas, tokens e configurações sensíveis.

✅ **Correção:**

+ Mover arquivos confidenciais para fora do `public_html`.
+ Usar `.htaccess` para bloquear acesso:

```apache
<Files .env>
    Order allow,deny
    Deny from all
</Files>
```

---

## 🔹 LARAVEL — Exemplos de **Security Misconfiguration**

### ❌ **1. `APP_DEBUG=true` em produção**

```env
APP_DEBUG=true
```

➡️ Mostra stack traces completos, incluindo variáveis de ambiente e SQLs.

✅ **Correção:**

```env
APP_DEBUG=false
APP_ENV=production
```

---

### ❌ **2. Falta de headers de segurança**

Laravel, por padrão, não inclui todos os headers de segurança recomendados.

✅ **Correção:**
Use o middleware do pacote [`spatie/laravel-csp`](https://github.com/spatie/laravel-csp) ou adicione manualmente:

```php
// app/Http/Middleware/SecurityHeaders.php
public function handle($request, Closure $next)
{
    $response = $next($request);
    $response->headers->set('X-Frame-Options', 'DENY');
    $response->headers->set('X-Content-Type-Options', 'nosniff');
    $response->headers->set('Referrer-Policy', 'no-referrer');
    $response->headers->set('Content-Security-Policy', "default-src 'self'");
    return $response;
}
```

---

### ❌ **3. Expor rotas sensíveis no `web.php`**

```php
Route::get('/telescope'); // ou /horizon sem proteção
```

➡️ Se não estiver protegido com autenticação, expõe informações internas.

✅ **Correção:**

```php
Route::middleware(['auth'])->group(function () {
    \Laravel\Telescope\Telescope::auth(function ($request) {
        return auth()->check() && auth()->user()->is_admin;
    });
});
```

---

## ✅ Dica final

A melhor forma de evitar a A05 é manter **uma checklist de segurança para deploy** com itens como:

+ `APP_DEBUG=false`
+ `.env` inacessível
+ permissões corretas
+ headers ativos
+ endpoints sensíveis autenticados

---

Quer que eu te ajude a criar um checklist de deploy seguro para PHP ou Laravel?

--==========================================================
--==========================================================
--==========================================================
--==========================================================
--==========================================================
--==========================================================
--==========================================================

## Perplexity

<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" class="logo" width="120"/>

# A05:2021-Configuração Incorreta de Segurança da OWASP Top 10

A categoria **A05:2021-Configuração Incorreta de Segurança** ocupa a 5ª posição no OWASP Top 10 2021, representando uma das vulnerabilidades mais críticas em aplicações web modernas. Caracterizada pela implementação inadequada de controles de segurança em componentes de software, infraestrutura ou serviços em nuvem, essa falha expõe sistemas a explorações que poderiam ser evitadas com configurações adequadas. Estudos indicam que **90% das aplicações** testadas apresentaram pelo menos uma forma de configuração insegura, com mais de 208 mil ocorrências documentadas de _Common Weakness Enumeration_ (CWE) relacionadas a essa categoria[^1][^3].

## Descrição e Contextualização Técnica

A configuração incorreta de segurança ocorre quando componentes da stack de tecnologia (servidores, bancos de dados, frameworks) não são protegidos adequadamente, permitindo que atacantes explorem brechas previsíveis. Essa vulnerabilidade é particularmente perigosa por sua natureza _silenciosa_ – muitas organizações não percebem que estão expostas até sofrerem um incidente.

### Mecanismos Subjacentes

1. **Configurações Padrão Não Modificadas**: Muitos sistemas são implantados com configurações de fábrica que priorizam facilidade de uso sobre segurança, como credenciais administrativas padrão (ex.: admin/senha) e portas de serviço desnecessárias abertas[^1][^6].
2. **Exposição de Informações Sensíveis**: Mensagens de erro detalhadas, _stack traces_ e páginas de diagnóstico expõem detalhes internos do sistema, fornecendo insights valiosos para atacantes[^1][^5].
3. **Falha na Atualização de Componentes**: Serviços desatualizados ou não corrigidos mantêm vulnerabilidades conhecidas, mesmo quando patches estão disponíveis[^1][^6].
4. **Permissões Excessivas**: Contas de serviço com privilégios elevados além do necessário aumentam a superfície de ataque[^2][^5].

Um estudo realizado na plataforma Moodle demonstrou que configurações incorretas estavam entre as cinco principais vulnerabilidades identificadas, afetando diretamente a integridade de ambientes educacionais digitais[^3].

## Estratégias de Prevenção e Mitigação

### Automação de Configurações Seguras

A adoção de **Infraestrutura como Código (IaC)** permite definir configurações de segurança de forma programática, garantindo consistência entre ambientes de desenvolvimento, teste e produção. Ferramentas como _Xygeni IaC Security_ automatizam a verificação de parâmetros críticos, como desabilitação de serviços não essenciais e aplicação de políticas de criptografia[^2][^5].

### Auditorias Contínuas

Processos de revisão periódica devem incluir:

+ Verificação de contas padrão e senhas não alteradas
+ Análise de permissões de arquivos e diretórios
+ Validação de cabeçalhos de segurança (ex.: Content-Security-Policy, X-Content-Type-Options)
+ Monitoramento de serviços expostos na rede[^1][^5]

### Princípio do Menor Privilégio

A restrição de acesso baseada em funções (_RBAC_) reduz o impacto potencial de configurações incorretas. Por exemplo, bancos de dados não devem ser acessíveis diretamente da internet, e contas de serviço devem ter privilégios limitados às operações estritamente necessárias[^2][^6].

### Remediação de Vulnerabilidades Conhecidas

A integração de scanners de vulnerabilidade em pipelines CI/CD ajuda a identificar componentes desatualizados ou mal configurados antes da implantação em produção. O OWASP recomenda o uso combinado de ferramentas como o **OWASP ZAP** para detecção automática de más configurações[^3][^5].

## Impactos e Casos Reais

### Consequências Operacionais

+ **Exfiltração de Dados**: Configurações incorretas em armazenamentos em nuvem (ex.: buckets S3 públicos) levaram a vazamentos massivos, como o caso da **Primeira Corporação Financeira Americana** em 2019, que expôs 885 milhões de registros[^2].
+ **Comprometimento de Sistemas**: O ataque ao **Twitter em 2020** explorou controles de acesso fracos em ferramentas internas, permitindo que invasores assumissem contas de alta visibilidade[^2].
+ **Paralisia Operacional**: O ransomware **WannaCry** (2017) aproveitou-se de sistemas Windows não atualizados com a correção MS17-010, demonstrando como a falha em aplicar patches críticos pode ter consequências globais[^5].

### Estudo de Caso: Violação do Target (2013)

Um exemplo clássico envolveu a cadeia de suprimentos da Target, onde credenciais de terceiro com acesso excessivo ao sistema de HVAC foram usadas como vetor inicial. A falta de segmentação de rede e monitoramento permitiu que os atacantes movessem-se lateralmente até os sistemas de pagamento, comprometendo dados de 40 milhões de cartões[^2][^5].

## Cenário Atual e Tendências

Com a adoção acelerada de tecnologias em nuvem e microsserviços, a complexidade das configurações aumentou exponencialmente. Dados do **Relatório de Ameaças da IBM (2023)** indicam que **68% das violações** envolvem erros de configuração, muitas vezes relacionados a APIs mal protegidas ou serviços de armazenamento expostos.

A ascensão de ambientes _serverless_ e containers introduziu novos desafios:

+ Funções AWS Lambda com permissões excessivas
+ Clusters Kubernetes sem políticas de NetworkPolicy
+ Registros de container públicos com imagens vulneráveis

Esses cenários demandam abordagens modernas, como a utilização de _policy engines_ (ex.: Open Policy Agent) para impor configurações seguras de forma centralizada[^5][^6].

## Recomendações para Implementação

1. **Modelo de Maturação de Configurações**:
    + **Nível Básico**: Remoção de contas padrão, desabilitação de serviços não utilizados
    + **Nível Intermediário**: Automação via ferramentas IaC, integração com scanners SAST/DAST
    + **Nível Avançado**: Adoção de _Security-as-Code_ e monitoramento contínuo com IA/ML[^2][^5]
2. **Framework de Referência**:
    + **CIS Benchmarks**: Diretrizes específicas por tecnologia para configurações seguras
    + **NIST SP 800-123**: Guia para proteção de servidores web
    + **ISO/IEC 27002**: Controles para gestão de operações de TI seguras[^1][^6]
3. **Cultura Organizacional**:
    + Treinamentos regulares em _Secure DevOps_
    + Exercícios de _red teaming_ para testar configurações defensivas
    + Programas de recompensa por identificação de más configurações[^2][^5]

## Conclusão

A configuração incorreta de segurança permanece uma ameaça persistente não por sua complexidade técnica, mas pela falta de processos sistemáticos para gerenciar ambientes cada vez mais dinâmicos. A solução exige uma combinação de automação inteligente, educação contínua e adoção de frameworks comprovados. Organizações que integram verificações de segurança em todas as fases do ciclo de vida de desenvolvimento (SDLC) reduzem em até 72% os incidentes relacionados a más configurações[^2][^5].

À medida que a indústria avança para arquiteturas distribuídas e multi-nuvem, a capacidade de manter configurações consistentes e seguras tornou-se não apenas uma prática recomendada, mas um imperativo estratégico para a sobrevivência dos negócios digitais.

<div style="text-align: center">⁂</div>

[^1]: https://owasp.org/Top10/pt_BR/A05_2021-Security_Misconfiguration/

[^2]: https://xygeni.io/pt/blog/owasp-top-10-and-their-remedies/

[^3]: https://repositorio.ufu.br/bitstream/123456789/38406/1/EstudoVulnerabilidadesOWASP.pdf

[^4]: https://www.samsung.com/br/support/model/SM-A055MZSGZTO/

[^5]: https://www.youtube.com/watch?v=bmMEBEeyAK4

[^6]: https://www.indusface.com/blog/owasp-security-misconfiguration/

[^7]: https://www.linkedin.com/pulse/understanding-owasp-top-10-tcm-security-inc-uca8e

[^8]: https://www.linkedin.com/pulse/lets-talk-cwe-1174-aspnet-misconfiguration-improper-model-trivedi-rsfhc

[^9]: https://owasp.org/www-project-cheat-sheets/

[^10]: https://owasp.org/Top10/pt_BR/

[^11]: https://owasp.org/Top10/A05_2021-Security_Misconfiguration/

[^12]: https://www.slideshare.net/slideshow/owasp-top-10-vulnerabilities-a5broken-access-control-a6security-misconfiguration/191308667

[^13]: https://www.dio.me/articles/owasp-principais-vulnerabilidades-e-remediacoes-mapeadas

[^14]: https://f5cloud.zendesk.com/hc/en-us/articles/25620730796439-How-to-mitigate-OWASP-Top-Ten-A05-2021-Security-Misconfiguration

[^15]: https://cecyber.com/owasp-top-10-web-application-security-risks-2021/

[^16]: https://www.youtube.com/watch?v=N6Ix1sbhtaw

[^17]: https://sitedefender.com.br/owasp-top-ten-2021/

[^18]: https://www.zerolynx.com/en/blogs/news/securitymisconfiguration

[^19]: https://blog.grancursosonline.com.br/owasp-top-10-de-2021-parte-03/

[^20]: https://blog.convisoappsec.com/owasp-top-10-como-aplicar/

[^21]: https://www.xlabs.com.br/blog/saiba-quais-sao-as-vulnerabilidades-do-top-10-da-owasp-2021/

[^22]: https://www.buscape.com.br/celular/conteudo/galaxy-a05-e-galaxy-a05s

[^23]: https://www.estrategiaconcursos.com.br/blog/10-riscos-seguranca-web-owasp/

[^24]: https://vertigo.com.br/seguranca-de-apis-confira-as-top-10-falhas-de-seguranca-do-owasp/

[^25]: https://www.canalti.com.br/seguranca-da-informacao/top-10-owasp-vulnerabilidades-de-seguranca

[^26]: https://melhormarcade.com.br/produto/samsung-galaxy-a05/

[^27]: https://cloud.google.com/architecture/owasp-top-ten-mitigation

[^28]: https://www.youtube.com/watch?v=c-4ELAETGUA

[^29]: https://ehgomes.com.br/reviews/smartphone-samsung-galaxy-a05-128gb-4gb-ram-custo-beneficio-e-desempenho/

[^30]: https://seginfo.com.br/2021/09/16/owasp-top-10-liberadas-as-vulnerabilidades-principais-de-2021/

[^31]: https://www.linkedin.com/pulse/understanding-a052021-security-misconfiguration-owasp-top-qrbtc

[^32]: https://appalachiatech.com/resources/blog1/the-owasp-top-10-security-misconfiguration

[^33]: https://www.f5.com/pdf/ebooks/preparing-for-the-new-owasp-top-10-and-beyond.pdf

[^34]: https://security.stackexchange.com/questions/270770/cwe-for-misconfigured-server-allows-insecure-https-request-to-ip-addressed-url

[^35]: https://github.com/3ls3if/Cybersecurity-Notes/blob/main/readme/owasp-top-10/web/a05-2021-security-misconfiguration.md

[^36]: https://www.vaadata.com/blog/security-misconfiguration-owasp-top-10-5/

[^37]: https://www.kiuwan.com/wp-content/uploads/2024/05/OWASP-2021-Ebook.pdf

[^38]: https://s4e.io/scan/parent/security-misconfiguration

[^39]: https://niccs.cisa.gov/education-training/catalog/security-innovation/mitigating-owasp-2021-security-misconfiguration

[^40]: https://www.securityjourney.com/post/owasp-top-10-security-misconfiguration-explained

[^41]: https://owasp.org/Top10/

[^42]: https://cwe.mitre.org/data/published/cwe_v1.6.pdf

[^43]: https://www.codecademy.com/learn/becp-22-web-security-fundamentals/modules/wdcp-22-web-security/cheatsheet

[^44]: https://www.codecademy.com/learn/owasp-top-10-security-misconfiguration/modules/misconfiguration-where/cheatsheet

[^45]: https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html

[^46]: https://wiki.owasp.org/images/7/72/OWASP_Top_10-2017_(en).pdf.pdf

[^47]: https://cheatsheetseries.owasp.org/IndexProactiveControls.html

[^48]: https://sites.psu.edu/englishblogfa2023/sample-page/

[^49]: https://cheatsheetseries.owasp.org/Glossary.html

[^50]: https://wiki.owasp.org/images/9/9a/OWASP_Cheatsheets_Book.pdf

[^51]: https://portugese.opswat.com/blog/aws-s3-configuration-best-practice-enable-bucket-versioning-for-data-recovery

[^52]: https://www.elastic.co/pt/blog/advanced-tuning-finding-and-fixing-slow-elasticsearch-queries

[^53]: https://repost.aws/pt/knowledge-center/s3-configure-cors

[^54]: https://www.ibm.com/docs/pt-br/baw/22.x?topic=service-configuring-remote-elasticsearch

[^55]: https://owasp.org/Top10/pt_BR/A01_2021-Broken_Access_Control/

[^56]: https://www.checkpoint.com/pt/cyber-hub/cloud-security/what-is-aws-security/s3-bucket-security/top-3-s3-bucket-security-issues/

[^57]: https://thiagomont-portifolio.gitlab.io/portifolio/post/0008-elasticsearch-para-leigos

[^58]: https://docs.aws.amazon.com/pt_br/AmazonS3/latest/userguide/creating-buckets-s3.html

[^59]: https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-elasticsearch-on-ubuntu-18-04-pt

[^60]: https://docs.aws.amazon.com/pt_br/AmazonS3/latest/userguide/cors-troubleshooting.html

[^61]: https://owasp.org/www-project-developer-guide/draft/implementation/documentation/cheatsheets/

[^62]: https://cheatsheetseries.owasp.org/index.html

[^63]: https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration

[^64]: https://www.youtube.com/watch?v=N6Ix1sbhtaw

[^65]: https://cheatography.com/clucinvt/cheat-sheets/owasp-top-10-vulnerabilities/

[^66]: https://cdn2.hubspot.net/hubfs/4738670/A4-OWASP-Cheat-Sheet.pdf

[^67]: https://www.checkpoint.com/pt/cyber-hub/cloud-security/what-is-application-security-appsec/owasp-top-10-vulnerabilities/

[^68]: https://www.cloudflare.com/pt-br/learning/security/threats/owasp-top-10/

[^69]: https://www.akamai.com/pt/blog/security/owasp-top-10-api-security-risks-2023-edition

[^70]: https://docs.aws.amazon.com/pt_br/AmazonS3/latest/userguide/security-best-practices.html

[^71]: https://experienceleague.adobe.com/pt-br/docs/commerce-on-cloud/user-guide/configure/service/elasticsearch

[^72]: https://www.f5.com/pt_br/glossary/owasp
