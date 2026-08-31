# MAGI Sprint 5.3.2 — Campaign Stop/Cancel Fix

## Correção principal

Pausar uma Campaign agora é uma barreira operacional real:

- cancela jobs `pending` e `running` associados à Campaign;
- marca paths `queued/running` como `cancelled`;
- fecha o ciclo ativo com `stop_reason=campaign_paused`;
- coloca a execução em `paused` e impede novos ciclos;
- o endpoint de claim do Runner não entrega jobs de Campaign pausada/cancelada/concluída;
- resultado tardio de um job já cancelado não reabre nem sobrescreve o estado cancelado;
- remover uma Campaign também limpa seus jobs pendentes/em execução.

## Observação sobre job que já iniciou no processo local

O backend cancela imediatamente a propriedade lógica do job. Se o processo local do Runner já entrou dentro de um executor no exato momento do clique em Pausar, ele pode levar até o timeout individual desse executor para retornar ao loop; o resultado tardio é rejeitado e nenhum novo job da Campaign é entregue.
