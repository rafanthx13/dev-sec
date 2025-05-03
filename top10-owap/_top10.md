# 🔟 **OWASP Top 10 - Principais vulnerabilidades em aplicações web**

1. **A01:2021 - Quebra de Controle de Acesso (Broken Access Control)**  
    👉 Quando usuários acessam dados ou ações que não deveriam (ex: acessar dados de outro usuário ou páginas administrativas).

2. **A02:2021 - Falhas Criptográficas (Cryptographic Failures)**  
    👉 Uso incorreto de criptografia ou ausência dela, como dados sensíveis armazenados ou transmitidos sem proteção adequada (ex: sem HTTPS, senhas sem hash).

3. **A03:2021 - Injeção (Injection)**  
    👉 Quando comandos maliciosos são inseridos na aplicação (ex: **SQL Injection**, **Command Injection**) e são interpretados pelo sistema.

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
