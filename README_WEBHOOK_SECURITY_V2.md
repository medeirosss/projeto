# Centric v2 - Webhook seguro para alertas inbound

Esta versão adiciona **Configurações > Webhook** para proteger o endpoint:

```text
POST /api/actions/inbound-alert
```

## Regra de validação

1. Se o IP real de origem estiver em **Fontes confiáveis**, o POST é aceito sem token.
2. Se a origem não estiver nas fontes confiáveis, o backend exige o header:

```text
X-Centric-Webhook-Token: <token configurado>
```

3. Se o token estiver ausente ou inválido, o POST é bloqueado.
4. Se o webhook estiver desabilitado, o endpoint é bloqueado.

## Configurações > Webhook

Campos adicionados:

```text
Webhook habilitado
Token do webhook
Fontes confiáveis: IP/CIDR, uma por linha
Exigir token para origem externa
Aplicação atrás de proxy/reverse proxy
Proxies confiáveis: IP/CIDR, uma por linha
Header de IP real: X-Forwarded-For, X-Real-IP ou CF-Connecting-IP
```

## Segurança com proxy

Headers como `X-Forwarded-For` e `X-Real-IP` **só são aceitos** quando o IP que conectou diretamente na aplicação está listado em **Proxies confiáveis**.

Isso evita spoofing de IP por clientes externos.

## Exemplo PowerShell com token

```powershell
$uri = "http://SEU_SERVIDOR:8443/api/actions/inbound-alert"
$token = "TOKEN_CONFIGURADO"

$payload = @{
    source_system = "ADAuditPlus"
    event_number = "4625"
    event_type = "Failed Logon"
    event_type_text = "Failure"
    display_name = "Multiple Failed Logon Attempts"
    username = "app4"
    account_name = "app4"
    target_user = "app4"
    hostname = "SRV-AD-01"
    ip_address = "192.168.0.50"
    severity = "Alta"
    mitre_tactic = "Credential Access"
    mitre_technique = "T1110"
    nist_control = "AC-7"
    event_time = (Get-Date).ToString("o")
} | ConvertTo-Json -Depth 10

Invoke-RestMethod `
    -Uri $uri `
    -Method POST `
    -Headers @{ "X-Centric-Webhook-Token" = $token } `
    -ContentType "application/json" `
    -Body $payload
```

## Exemplo sem token

Configure em **Fontes confiáveis**:

```text
192.168.0.100
192.168.0.0/24
```

Qualquer POST originado dessas fontes será aceito sem token.
