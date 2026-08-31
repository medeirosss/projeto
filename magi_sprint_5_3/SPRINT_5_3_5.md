# Sprint 5.3.5 - Runner HTTP keep-alive hotfix

## Sintoma
O backend registrava diversas chamadas `GET /api/runners/jobs/next` com `200 OK`, enquanto o Runner intercalava `RemoteDisconnected("Remote end closed connection without response")`.

## Causa
O Runner mantinha uma `requests.Session` com HTTP/1.1 keep-alive. O Uvicorn encerra conexões keep-alive ociosas após um curto timeout. Como o intervalo de polling do Runner pode coincidir com esse limite, o cliente podia reutilizar um socket já fechado pelo servidor/proxy Docker Desktop. Essa tentativa falha antes de alcançar a aplicação, portanto não aparece no access log do Uvicorn.

## Correção
O cliente HTTP do Runner agora envia `Connection: close` em todas as requisições. Cada polling/heartbeat usa uma conexão TCP nova, eliminando a reutilização de sockets keep-alive obsoletos através do Windows/Docker NAT.

A serialização da sessão introduzida na 5.3.4 foi preservada.
