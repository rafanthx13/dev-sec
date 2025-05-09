# 🔟 **OWASP Top 10 - Principais vulnerabilidades em aplicações web**

1. **A01:2021 - Quebra de Controle de Acesso (Broken Access Control)**  
    👉 Quando usuários acessam dados ou ações que não deveriam (ex: acessar dados de outro usuário ou páginas administrativas).

2. **A02:2021 - Falhas Criptográficas (Cryptographic Failures)**  
    👉 Uso incorreto de criptografia ou ausência dela, como dados sensíveis armazenados ou transmitidos sem proteção adequada (ex: sem HTTPS, senhas sem hash).

3. **A03:2021 - Injeção (Injection)**  
    👉 Quando comandos maliciosos são injetados (mandados pelo usuário para o server) na aplicação (ex: **SQL Injection**, **Command Injection**) e são interpretados pelo sistema.

4. **A04:2021 - Design Inseguro (Insecure Design)**  
    👉 Falta de princípios seguros desde a concepção do sistema, como ausência de validações ou lógicas mal planejadas que abrem brechas.

5. **A05:2021 - Configuração Incorreta de Segurança (Security Misconfiguration)**  
    👉 Configurações padrão, permissões incorretas, servidores com informações sensíveis abertas, etc.

6. **A06:2021 - Componentes Vulneráveis e Desatualizados (Vulnerable and Outdated Components)**  
    👉 Uso de bibliotecas ou pacotes com falhas conhecidas, como versões antigas de frameworks.

7. **A07:2021 - Falhas de Identificação e Autenticação (Identification and Authentication Failures)**  
    👉 Senhas fracas, falta de autenticação multifator, sessões mal gerenciadas.

8. **A08:2021 - Falhas de Integridade em Dados e Software (Software and Data Integrity Failures)**  
    👉 Dados ou atualizações manipulados por terceiros, como atualizações sem verificação de assinatura.

9. **A09:2021 - Falhas em Registro e Monitoramento de Segurança (Security Logging and Monitoring Failures)**  
    👉 Falta de registros ou alertas para detectar atividades suspeitas (ex: logins suspeitos não são notificados).

10. **A10:2021 - Server-Side Request Forgery (SSRF)**  
    👉 A aplicação é induzida a fazer requisições para servidores internos que não deveriam estar expostos (ex: acessar `localhost` ou serviços internos via input do usuário).

# Tabela

|                         Top10                         | CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
|:-----------------------------------------------------:|:-----------:|:------------------:|:------------------:|:--------------------:|:-------------------:|:------------:|:------------:|:-----------------:|:----------:|
| A01:2021 – Broken Access Control                      |      34     |       55.97%       |        3.81%       |         6.92         |         5.93        |    94.55%    |    47.72%    |      318,487      |   19,013   |
| A02:2021 – Cryptographic Failures                     |      29     |       46.44%       |        4.49%       |         7.29         |         6.81        |    79.33%    |    34.85%    |      233,788      |    3,075   |
| A03:2021 – Injection                                  |      33     |       19.09%       |        3.37%       |         7.25         |         7.15        |    94.04%    |    47.90%    |      274,228      |   32,078   |
| A04:2021 – Insecure Design                            |      40     |       24.19%       |        3.00%       |         6.46         |         6.78        |    77.25%    |    42.51%    |      262,407      |    2,691   |
| A05:2021 – Security Misconfiguration                  |      20     |       19.84%       |        4.51%       |         8.12         |         6.56        |    89.58%    |    44.84%    |      208,387      |     789    |
| A06:2021 – Vulnerable and Outdated Components         |      3      |       27.96%       |        8.77%       |         5.00         |         5.00        |    51.78%    |    22.47%    |       30,457      |      0     |
| A07:2021 – Identification and Authentication Failures |      22     |       14.84%       |        2.55%       |         7.40         |         6.50        |    79.51%    |    45.72%    |      132,195      |    3,897   |
| A08:2021 – Software and Data Integrity Failures       |      10     |       16.67%       |        2.05%       |         6.94         |         7.94        |    75.04%    |    45.35%    |       47,972      |    1,152   |
| A09:2021 – Security Logging and Monitoring Failures   |      4      |       19.23%       |        6.51%       |         6.87         |         4.99        |    53.67%    |    39.97%    |       53,615      |     242    |
| A10:2021 – Server-Side Request Forgery (SSRF)         |      1      |        2.72%       |        2.72%       |         8.28         |         6.72        |    67.72%    |    67.72%    |       9,503       |     385    |
