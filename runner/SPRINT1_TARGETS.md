# Sprint 1 — Alvos e descoberta Nmap

## Escopo

A Sprint 1 cria um cadastro próprio de alvos do Magi e executa a descoberta diretamente no backend. O Runner e o Endpoint Central não participam deste fluxo.

## Dados coletados

- hostname, quando resolvido pelo Nmap;
- IPv4;
- MAC, quando visível na camada 2;
- primeira e última detecção.

## Regras de correlação

1. MAC normalizado igual;
2. hostname normalizado igual, quando não houver conflito de MAC;
3. IP atual igual;
4. criação de um novo `target_uuid`.

## Build e implantação

A imagem deve ser reconstruída com o Dockerfile incluído no pacote. O Compose concede `NET_RAW` ao backend.

```powershell
docker compose build
docker compose up -d
```

Em ambientes que consomem imagem do GHCR, publique uma nova tag e atualize o campo `image` do Compose antes do `pull`.

## Testes

```powershell
docker exec magi_backend nmap --version
docker exec magi_backend nmap -sn -oX - 192.168.0.0/24
```

Na aplicação:

1. abra **Alvos**;
2. informe um IPv4 ou CIDR;
3. clique em **Iniciar descoberta**;
4. confirme a criação dos registros;
5. execute novamente e confirme a atualização da última detecção;
6. em um cenário DHCP, confirme que o mesmo MAC mantém o `target_uuid` e registra o IP anterior em `target_addresses`.

## Limitações conhecidas

- somente IPv4 e CIDR IPv4;
- limite inicial de /16;
- MAC pode não estar disponível em redes roteadas ou conforme o modo de rede do Docker;
- a execução é síncrona e possui timeout de 300 segundos;
- CPU, memória e disco não fazem parte desta sprint.
