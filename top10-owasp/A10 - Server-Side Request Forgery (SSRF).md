# A10:2021 - Server-Side Request Forgery (SSRF)

É a CWE-918 (Server-Side Request Forgery (SSRF))

https://cwe.mitre.org/data/definitions/918.html

## Liks youtube

+ https://www.youtube.com/watch?v=RecYP7vasYY&ab_channel=WhiteHatBrasil
+ https://www.youtube.com/watch?v=-S9Ce6eIVS4&ab_channel=GuiadeAppSec

## Links

+ https://www.imperva.com/learn/application-security/server-side-request-forgery-ssrf/#:~:text=Attack%20Types-,What%20Is%20SSRF?,them%20to%20read%20the%20data.
+ Blog interessante: https://blog.crowsec.com.br/
    + Link do srf: https://blog.crowsec.com.br/test/
+ Site TOP PT-BR (NO TA 10) :: https://owasp.org/Top10/pt_BR/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
+ https://www.imperva.com/learn/application-security/server-side-request-forgery-ssrf/#:~:text=Attack%20Types-,What%20Is%20SSRF?,them%20to%20read%20the%20data.
+ Exmplocrar mais depois :: https://rodolfomarianocy.medium.com/ssrf-entenda-o-b%C3%A1sico-de-forma-simples-e-algumas-formas-de-bypass-e694751acc0e
+ Burp Sute :: https://portswigger.net/web-security/ssrf
+ (top) https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md

## Refes

+ https://www.siteblindado.com/blog/single-post/server-side-request-forgery-x-cross-site-request-forgery#:~:text=O%20Server%2DSide%20Request%20Forgery%20(SSRF)%20%C3%A9%20um%20tipo,recursos%20dentro%20da%20rede%20interna.

## Do owap top 10

+ A10:2021-Server-Side Request Forgery is added from the Top 10 community survey (#1). The data shows a relatively low incidence rate with above average testing coverage, along with above-average ratings for Exploit and Impact potential. This category represents the scenario where the security community members are telling us this is important, even though it’s not illustrated in the data at this time.
    + É uma categoria nova se comapra 2017 com 2021

## O que é

**As falhas de SSRF ocorrem sempre que um aplicativo da web busca um recurso remoto sem validar a URL fornecida pelo usuário**

Ele permite que um invasor force o aplicativo a enviar uma solicitação criada para um destino inesperado, mesmo quando protegido por um firewall, VPN ou outro tipo de lista de controle de acesso à rede (ACL).

Como os aplicativos da web modernos fornecem aos usuários finais recursos convenientes, buscar uma URL se torna um cenário comum. Como resultado, a incidência de SSRF está aumentando. Além disso, a gravidade do SSRF está se tornando mais alta devido aos serviços em nuvem e à complexidade crescente das arquiteturas.

O Server-Side Request Forgery (SSRF) é um tipo de ciberataque onde o agressor explora a capacidade de um servidor fazer solicitações a outros servidores ou recursos dentro da rede interna.

Ocorre quando: **UMA APLICAÇAO FAZ UMA REQUISIÇÃO A OUTRA APARTIR DE UMA ENTRADA FORNECEIDA/QUE PODE SER ALTERADA PELO USUÁRIO**

O ponto de preocupação se encontra em ambientes que utilizam APIs e micros serviços, onde os servidores frequentemente fazem solicitações a diversos outros serviços.

Aqui, o cibercriminoso explora a capacidade do servidor de fazer requisições a outros sistemas, potencialmente acessando informações sensíveis ou executando comandos maliciosos.

SSRF busca, de alguma forma, manipular o servidor para acessar ou comprometer recursos internos

---

usar a infraestrutura da própria aplicação para:

Fazer varredura interna (intranet, localhost, outros serviços)

Roubar informações de metadados de nuvem

Executar chamadas em nome do servidor, muitas vezes autenticado automaticamente por IP.

✅ Como corrigir

+ Validar e restringir URLs

+ Permitir apenas domínios específicos

+ Bloquear endereços internos e IPs privados

+ Não confiar no hostname – resolver e bloquear IPs diretamente

+ Usar firewalls ou containers com regras de rede

## Como mitigar

+ Primeiro, é vital implementar uma validação rigorosa de entradas, garantindo que todas as solicitações de URLs sejam seguras e legítimas.
+ Uma estratégia eficaz inclui a criação de listas de permissões, limitando as solicitações externas a fontes confiáveis.
+ Além disso, a segmentação de redes, isolando a infraestrutura interna, pode limitar significativamente o alcance de um ataque SSRF.
+ Monitorar e registrar solicitações também é crucial para identificar padrões suspeitos que possam indicar um ataque em andamento.

+ Higienize e valide todos os dados de entrada fornecidos pelo cliente;
+ Aplique o esquema de URL, porta e destino com uma lista de permissões positiva;
+ Não envie a resposta crua ao cliente
+ Desabilite redirecionamentos de HTTP;
+ Tenha cuidado com a consistência URL contra ataques que mirem a resolução de nomes através do DNS e CWE-367

## cenário de exemplo de um ataque

Os invasores podem usar SSRF para atacar sistemas protegidos por firewalls de aplicativos da web, firewalls ou ACLs de rede, usando cenários como:

Cenário #1: Varredura de portas em servidores internos - se a arquitetura de rede não for segmentada, os invasores podem mapear as redes internas e determinar se as portas estão abertas ou fechadas em servidores internos a partir dos resultados da conexão ou do tempo decorrido para conectar ou rejeitar as conexões de carga SSRF.

Cenário #2: Exposição de dados confidenciais - os invasores podem acessar arquivos locais, como ou serviços internos, para obter informações confidenciais, como file:///etc/passwd e http://localhost:28017/.

Cenário #3: Acesse o armazenamento de metadados de serviços em nuvem - a maioria dos provedores de nuvem possui armazenamento de metadados, como http://169.254.169.254/. Um invasor pode ler os metadados para obter informações confidenciais.

Cenário #4: Comprometimento dos serviços internos - O invasor pode abusar dos serviços internos para conduzir outros ataques, como Execução Remota de Código/Remote Code Execution (RCE) ou Negação de Serviço/Denial of Service (DoS).

## Exemplo no php puro (CHATGPT)

````php
<?php
// Exemplo vulnerável de SSRF em PHP puro
$url = $_GET['url']; // Sem validação!
$response = file_get_contents($url); // Retorna como string o conteudo de uma URL
echo $response;
````

Se na url a pessoa passar um link como rodar o link a seguir:

````
http://example.com/ssrf.php?url=http://localhost:8080/admin
````

Vai fazer um GET ou até me seguinte

````
http://localhost:8080/admin
````

ou até mesmo pegar o conteudo do arquivo.

### Mitigar: Santetizar a entrada

````php
<?php
function is_valid_url($url) {
    $parsed = parse_url($url);
    $host = gethostbyname($parsed['host']);
    // Evita IPs privados
    if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        return true;
    }
    return false;
}

$url = $_GET['url'];
if (is_valid_url($url)) {
    echo file_get_contents($url);
} else {
    http_response_code(400);
    echo "URL não permitida.";
}

````

### Boa prática

+ Nunca aceite URLs externas diretamente do usuário sem validação
+ Use uma lista branca de domínios confiáveis
+ Bloqueie IPs privados (127.0.0.1, 10.0.0.0/8 etc.)
+ Defina timeouts e limites de resposta
+ Use firewalls para limitar acesso interno
