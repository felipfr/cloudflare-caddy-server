# Configurando um servidor local seguro com o Cloudflare e Caddy

Hoje em dia, é cada vez mais comum utilizar serviços de DNS dinâmico para acessar dispositivos na rede local. Esses serviços permitem que os usuários criem nomes de domínio personalizados para acessar seus dispositivos em casa, como computadores, servidores e câmeras, usando um endereço de IP dinâmico. Isso pode ser muito útil para acessar seus arquivos, servidor web e monitorar suas câmeras, no entanto, é importante estar ciente dos riscos associados ao uso desses serviços:

- **Segurança:** Com seu IP e porta exposto na Internet, você está sujeito a invasões, ataques DDoS, rastreamento das suas atividades e vários outros riscos;
- **Vulnerabilidades:** Se houver alguma vulnerabilidade, os invasores podem explorá-las para acessar sua rede e dispositivos;
- **Monitoramento:** Se você estiver usando para acessar dispositivos com câmeras, é importante ter em mente que as imagens e vídeos podem ser acessados por terceiros sem o seu conhecimento;

Neste guia, vou te mostrar como fazer a configuração do seu próprio serviço de DNS dinâmico no Windows, utilizando formas de proteção mais seguras e realizando a conexão via HTTPS com um certificado válido. Vamos utilizar um domínio próprio, o serviço da Cloudflare e o Caddy.

### Domínio

Como não iremos depender do serviço de DNS de terceiros, você precisará registrar um domínio próprio. Existem vários tipos de domínio, com todos os tipos de preços, pagos anualmente. Recomendo o [Google Domains](https://domains.google).

### Cloudflare

A Cloudflare é uma [Content Delivery Network (CDN)](https://www.cloudflare.com/pt-br/learning/cdn/what-is-a-cdn/), oferecendo um melhor desempenho e velocidade, porém o que mais nos interessa são as diversas medidas de segurança, como proteção DDoS, detecção de malware, bloqueio de IP's suspeitos, o que ajuda a proteger o seu servidor de ataques externos.

### Caddy

O Caddy é um servidor web de código aberto escrito na linguagem [Go](https://pt.wikipedia.org/wiki/Go_(linguagem_de_programa%C3%A7%C3%A3o)). Ele é conhecido por sua configuração simples e automatização de tarefas comuns, como configuração de SSL e redirecionamentos. Iremos configurá-lo como um proxy reverso, o que significa que ele poderá encaminhar solicitações de clientes para outros servidores. Isso é útil quando você tem várias aplicações em diferentes portas e deseja utilizá-las em um único endereço. Outra vantagem é não precisar ficar redirecionando portas no roteador a cada serviço utilizado, já que o Caddy recebe as solicitações pela Internet e faz o redirecionamento para as portas na rede local.

## Configurando o domínio na Cloudflare



O primeiro passo é a criação do domínio. Não irei entrar em detalhes, pois é bastante simples. Após ter o domínio criado, vamos fazer o cadastro na Cloudflare, onde após preencher as informações, irá solicitar para que você mude os endereços de DNS no paínel de controle do seu domínio, para que o mesmo possa apontar para os DNS's da Cloudflare.

Com o seu domínio apontado para o Cloudflare, iremos começar a configuração.

Entre no paínel da Cloudflare, selecione o seu domínio e vá até a aba **DNS > Registros**.

Na tabela de gerenciamento, apague todos os registros e deixe apenas o principal, do tipo A. Vá em editar e na parte "**Endereço IPv4**" coloque o seu endereço IP, que você pode descobrir através do site meuip.com.br. Deixe o "Status do Proxy" como ativo e o "**TTL**" em Auto.

![](https://i.ibb.co/9gs3nXf/Imagem-01.png)

Feito isso, agora iremos criar um certificado de origem, emitido pela Cloudflare, para que possamos criptografar o tráfego entre o seu servidor e a Internet.

Primeiro, vá a aba **SSL/TLS > Visão Geral** e deixe o modo de criptografia como "**Completo**".

![](https://i.ibb.co/kJ7tjpw/Imagem-02.png)

Depois, vá até "**Servidor de Origem**" e crie um novo certificado, deixando as configurações como padrão. Ela vai gerar um certificado e sua chave privada, com validade de 15 anos.

Crie dois arquivos de texto no notepad e cole o código do certificado e da chave, que foram mostrados na tela. Depois, renomeie o tipo dos arquivos, de .txt para .pem. Coloque os dois em alguma pasta, recomendo criar uma pasta para o Caddy e colocar o certificado e a chave lá dentro, para ficar mais organizado.

Ainda em "**Servidor de Origem**", ative a opção "**Pulls de origem autenticados**", que permite que o conteúdo armazenado em um servidor de origem seja acessado somente por meio de uma autenticação válida. Isso significa que, antes de acessar o conteúdo armazenado no servidor de origem, um usuário ou dispositivo deve fornecer credenciais válidas para o Cloudflare. Isso ajuda a proteger o conteúdo armazenado no servidor de origem contra acesso não autorizado ou abuso. Após ativar, baixe [esse certificado](https://developers.cloudflare.com/ssl/static/authenticated_origin_pull_ca.pem) e coloque na mesma pasta do que foi gerado antes.

## Configurando o Caddy

É bem simples, vá até a [página](https://developers.cloudflare.com/ssl/static/authenticated_origin_pull_ca.pem), selecione a sua arquitetura (normalmente "**Windows amd64**") e faça o download. Depois, renomeie o arquivo para "**caddy.exe**" e coloque na pasta que você criou anteriormente.

Crie um arquivo de texto chamado "**caddyfile**" e apague a extensão .txt, deixando sem extensão alguma.

Agora, abra o arquivo "**caddyfile**" no editor de texto e configure da seguinte forma (troque os caminhos dos arquivos pelos seus):

```
seudominio.com {
   tls C:\Server\Caddy\Cloudflare\certificado.pem C:\Server\Caddy\Cloudflare\chave.pem {
      client_auth {
         mode require_and_verify
         trusted_ca_cert_file C:\Server\Caddy\Cloudflare\authenticated_origin_pull_ca.pem
      }
   }
}
```



Baixe o [**NSSM**](https://nssm.cc/download) e coloque em uma pasta com o mesmo nome. Vá até ela usando o prompt de comando, com privilégios de administrador e execute:

```
nssm install Caddy
```

Irá abrir uma janela. Selecione em "**Path**" o arquivo "**caddy.exe**" e em "**Arguments**" escreva "run". Clique em "**Install Service**" e depois execute o comando no prompt:

```
nssm start Caddy
```

O serviço deve iniciar e não será necessário executar manualmente outra vez, a menos que algo mude.

Vá até as configurações avançadas do Firewall do Windows e crie uma regra de entrada, liberando as seguintes portas TCP:

- 80: necessária para a comunicação HTTP;
- 443: necessária para a comunicação HTTPS;
- 2019: necessária para a comunicação do Caddy;

Faça o mesmo no seu roteador, encaminhando as portas para o IP do computador em que o Caddy está instalado. 

## Configurando o script para atualizar o IP no Cloudflare



Para que o Cloudflare atualize seu IP toda vez que ele mudar, é necessário o uso de um script do PowerShell. A versão do aplicativo tem que ser acima da 7.1 e ter permissões para rodar scripts de terceiros. Se não tiver habilitado, recomendo a leitura [desse artigo](https://lazyadmin.nl/powershell/running-scripts-is-disabled-on-this-system/).

O script é esse:

```
#requires -Version 7.1

[cmdletbinding()]
param (
    [parameter(Mandatory)]
    $Email,
    [parameter(Mandatory)]
    $Token,
    [parameter(Mandatory)]
    $Domain,
    [parameter(Mandatory)]
    $Record
)

# Build the request headers once. These headers will be used throughout the script.
$headers = @{
    "X-Auth-Email"  = $($Email)
    "Authorization" = "Bearer $($Token)"
    "Content-Type"  = "application/json"
}

#Region Token Test
## This block verifies that your API key is valid.
## If not, the script will terminate.

$uri = "https://api.cloudflare.com/client/v4/user/tokens/verify"

$auth_result = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers -SkipHttpErrorCheck
if (-not($auth_result.result)) {
    Write-Output "API token validation failed. Error: $($auth_result.errors.message). Terminating script."
    # Exit script
    return
}
Write-Output "API token validation [$($Token)] success. $($auth_result.messages.message)."
#EndRegion

#Region Get Zone ID
## Retrieves the domain's zone identifier based on the zone name. If the identifier is not found, the script will terminate.
$uri = "https://api.cloudflare.com/client/v4/zones?name=$($Domain)"
$DnsZone = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers -SkipHttpErrorCheck
if (-not($DnsZone.result)) {
    Write-Output "Search for the DNS domain [$($Domain)] return zero results. Terminating script."
    # Exit script
    return
}
## Store the DNS zone ID
$zone_id = $DnsZone.result.id
Write-Output "Domain zone [$($Domain)]: ID=$($zone_id)"
#End Region

#Region Get DNS Record
## Retrieve the existing DNS record details from Cloudflare.
$uri = "https://api.cloudflare.com/client/v4/zones/$($zone_id)/dns_records?name=$($Record)"
$DnsRecord = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers -SkipHttpErrorCheck
if (-not($DnsRecord.result)) {
    Write-Output "Search for the DNS record [$($Record)] return zero results. Terminating script."
    # Exit script
    return
}
## Store the existing IP address in the DNS record
$old_ip = $DnsRecord.result.content
## Store the DNS record type value
$record_type = $DnsRecord.result.type
## Store the DNS record id value
$record_id = $DnsRecord.result.id
## Store the DNS record ttl value
$record_ttl = $DnsRecord.result.ttl
## Store the DNS record proxied value
$record_proxied = $DnsRecord.result.proxied
Write-Output "DNS record [$($Record)]: Type=$($record_type), IP=$($old_ip)"
#EndRegion

#Region Get Current Public IP Address
$new_ip = Invoke-RestMethod -Uri 'https://v4.ident.me'
Write-Output "Public IP Address: OLD=$($old_ip), NEW=$($new_ip)"
#EndRegion

#Region update Dynamic DNS Record
## Compare current IP address with the DNS record
## If the current IP address does not match the DNS record IP address, update the DNS record.
if ($new_ip -ne $old_ip) {
    Write-Output "The current IP address does not match the DNS record IP address. Attempt to update."
    ## Update the DNS record with the new IP address
    $uri = "https://api.cloudflare.com/client/v4/zones/$($zone_id)/dns_records/$($record_id)"
    $body = @{
        type    = $record_type
        name    = $Record
        content = $new_ip
        ttl     = $record_ttl
        proxied = $record_proxied
    } | ConvertTo-Json

    $Update = Invoke-RestMethod -Method PUT -Uri $uri -Headers $headers -SkipHttpErrorCheck -Body $body
    if (($Update.errors)) {
        Write-Output "DNS record update failed. Error: $($Update[0].errors.message)"
        ## Exit script
        return
    }

    Write-Output "DNS record update successful."
    return ($Update.result)
}
else {
    Write-Output "The current IP address and DNS record IP address are the same. There's no need to update."
}
#EndRegion
```

Salve na pasta com o nome de "**Update-CloudflareDDNS.ps1**". Para não ser preciso executar o script de forma manual toda vez que precisar atualizar, vamos criar uma tarefa agendada no Windows, em que o script será executado toda vez de forma automática.

Abra o PowerShell usando privilégios de administrador e execute o código abaixo, editando antes com as suas informações:

```
# Define the scheduled task action properties
## Enter the PowerShell script path
$scriptPath = 'C:\CloudflareDDNS\Update-CloudflareDDNS.ps1'
## Cloudflare account's email address
$Email = 'june.castillote@gmail.com'
## Cloudflare API Token
$Token = 'kGW8n........eJl5a'
## DNS Domain Name
$Domain = 'lazyexchangeadmin.cyou'
## DNS Record to Update
$Record = 'demo.lazyexchangeadmin.cyou'

# Create the scheduled task action object
$taskAction = New-ScheduledTaskAction `
    -Execute "pwsh.exe" `
    -Argument "-File $scriptPath -Email $Email -Token $Token -Domain $Domain -Record $Record"
```

- Localização do script "**Update-CloudflareDDNs**" no seu computador;
- Email de cadastro na Cloudflare;
- API Token: [Crie um token aqui](https://dash.cloudflare.com/profile/api-tokens), usando o modelo "**Editar DNS de Zona**" e selecionando o seu domínio em "**Recursos de Zona**". Após isso ele irá gerar o código;
- Domínio principal (ex: dominio.com);
- Registro que você quer atualizar (ex: dominio.com ou cloud.dominio.com);  

Após executar, será necessário criar um gatilho:

```
# Create a new scheduled task trigger schedule
## Trigger = every 3 minutes for 10 years.
$taskTrigger = New-ScheduledTaskTrigger `
-Once `
-At (Get-Date -Minute 0 -Second 0) `
-RepetitionInterval (New-TimeSpan -Minutes 3) `
-RepetitionDuration (New-TimeSpan -Days 3650)
```

E agora, criando uma nova tarefa no sistema:

```
# Register the scheduled task in the system.
## Scheduled Task Name
$TaskName = 'Update Cloudflare Dynamic DNS'
## Scheduled Task Description
$Description = 'Update Cloudflare DDNS Entry every 3 minutes'
## Create the scheduled task
Register-ScheduledTask `
-TaskName $TaskName `
-Description $Description `
-Action $taskAction `
-Trigger $taskTrigger `
-User 'NT AUTHORITY\SYSTEM'
```

Com isso, o seu IP será atualizado na Cloudflare a cada 3 minutos de forma automática. Você pode editar o código e colocar o tempo que achar melhor, ou até mesmo editar no agendador de tarefas do Windows, mudando da forma que precisar.

## Finalizando

Depois de tudo configurado, você agora possui um servidor com suporte ao HTTPS, usando criptografia de ponta a ponta para proteger as informações transmitidas, e uma defesa robusta, possuindo diversas camadas de proteção contra ataques de negação de serviço (DDoS), injeção de SQL, cross-site scripting (XSS) e outras ameaças comuns. Mas como você estará exposto a Internet, é importante lembrar que nunca há uma garantia total de segurança. Recomendo sempre manter seus sistemas e aplicativos atualizados e monitorar regularmente as atividades de rede para detectar qualquer atividade suspeita.

Para configurar algum serviço no Caddy é bem simples, bastando adicionar algumas linhas ao arquivo "**caddyfile**". Vou usar de exemplo a configuração do "**Nextcloud**" e do monitoramento das câmeras de segurança:

```
seudominio.com {
   tls C:\Server\Caddy\Cloudflare\certificado.pem C:\Server\Caddy\Cloudflare\chave.pem {
      client_auth {
         mode require_and_verify
         trusted_ca_cert_file C:\Server\Caddy\Cloudflare\authenticated_origin_pull_ca.pem
      }
   }
}
cloud.seudominio.com {
    reverse_proxy ip_na_rede_local:9000
}
camera.seudominio.com {
    reverse_proxy ip_na_rede_local:51478
}


```

Se estiver rodando na mesma máquina que o Caddy, pode ser colocado tanto "**localhost**" como o endereço de IP da máquina na rede local. Agora, serviços de câmera que geralmente funcionam em DVRs, é só colocar o endereço de IP e em ambos os casos, acompanhados do número da porta.

Para cada serviço que for utilizar, será necessário a criação de um novo subdomínio na Cloudflare. É só escolher seu site, ir na aba DNS e fazer a criação de um novo registro do tipo CNAME, com o nome do subdomínio (ex: cloud) e o destino (ex: seudominio.com). 

Espero que tenha conseguido ajudar de alguma forma.
