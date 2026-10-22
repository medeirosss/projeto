# Test Plan — Sprint 3.0

1. Atualize backend e Runner e confirme `alembic heads` em `20260807_0020`.
2. Confirme Runner `2.12.0` e Nmap disponível com `--doctor`.
3. Crie um novo scan com **Service Discovery** habilitado.
4. Execute o scan de um host conhecido com pelo menos uma porta TCP aberta.
5. Acompanhe o pipeline: Discovery, DNS, Fingerprint, Classificação, Service Discovery, Inventário.
6. Confirme que a etapa Service Discovery só inicia para hosts confirmados pelo Discovery.
7. Em **Ativos analisados**, confirme que a coluna Serviços possui uma contagem.
8. Clique na contagem e valide porta, protocolo, nome amigável, categoria, produto e versão quando o Nmap fornecer.
9. Repita o mesmo scan e confirme que `asset_services` não duplica portas; `last_seen_at` deve atualizar.
10. Abra uma nova porta em um ativo de teste e repita o scan; `new_services_count` deve aumentar.
11. Feche uma porta e repita o scan; ela deve sair da visão atual (`active=false`) sem apagar o histórico.
12. Teste um scan com Service Discovery desabilitado; o pipeline deve indicar a etapa como ignorada.
13. Teste um host onde `-sV` falhe ou exceda timeout; o ativo deve permanecer no inventário e a falha deve aparecer no pipeline.
