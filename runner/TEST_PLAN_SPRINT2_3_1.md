# Test Plan — Sprint 2.3.1

1. Execute um scan já conhecido e confirme que os ativos continuam em **Ativos analisados** sem duplicidade.
2. Adicione uma máquina nova e execute o scan: ela deve aparecer em **Novos ativos** e também em **Ativos analisados**.
3. Abra **Scan** durante uma execução e confirme o pipeline: Discovery → DNS → Fingerprint → Classificação → Inventário.
4. Ao final, abra o detalhe do scan e confira os estados por ativo. Falhas parciais não podem retirar o ativo do inventário.
5. Em **Compliance**, configure no máximo 3 regras independentes (Servidor, Desktop e Nó de rede) usando Início/Contém/Final.
6. Execute novo scan e clique na pontuação de um ativo para ver as evidências positivas/negativas.
7. Confira a aba **Pontuação** e valide que os pesos exibidos são os mesmos usados no cálculo.
8. Configure cleanup com 3 scans de teste, deixe um ativo ausente pelo limite e confirme que ele some do inventário sem apagar o target histórico.
9. Faça o ativo reaparecer e confirme reativação automática com o mesmo target_uuid.
10. Se um ativo estiver associado a dois scans, a ausência em um scan não deve retirá-lo se o outro o detectou em sua última execução.
