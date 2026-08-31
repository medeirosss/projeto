# Magi Sprint 1 v3 — Discovery via Runner

## Provider padrão

`DISCOVERY_PROVIDER=runner`

O backend mantém o `LocalNmapProvider` e o Nmap instalado na imagem Docker para uso futuro. Na Golden Image 1.0 para Windows/Docker Desktop, os scans são enviados ao Runner Windows.

## Requisitos do Runner

- Nmap instalado separadamente pelo administrador.
- O Magi não baixa nem instala Nmap ou Npcap.
- O Runner procura `nmap.exe` no PATH e nos diretórios padrão do Nmap.
- A ausência do Nmap não impede o serviço do Runner de iniciar; apenas desativa `nmap_discovery`.

## Fluxo

1. O usuário executa ou agenda um scan.
2. O backend seleciona um Runner online que anuncie `nmap_discovery.available=true`.
3. O backend cria um job `nmap_discovery`.
4. O Runner executa descoberta rápida `-sn -n -T4 --max-retries 1 --reason`.
5. O Runner devolve os hosts confirmados e o XML bruto.
6. O backend cria ou atualiza os Targets.

## Limites da versão 1.0

- IPv4.
- Host individual ou rede até `/24`.
- Nenhum parâmetro arbitrário de Nmap é aceito do frontend.
- IPs sem resposta não são cadastrados.

## Runner incluído

O diretório `runner/` contém o Magi Runner 2.11.0 com o executor `nmap_discovery`.
