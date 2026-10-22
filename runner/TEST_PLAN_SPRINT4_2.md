# Test Plan — Sprint 4.2

1. Instalação limpa do Runner sem Internet:
   - nuclei.exe presente
   - templates presentes
   - Doctor: Engine READY, Templates READY, Runtime Integrity OK

2. MAGI Native Check:
   - host inexistente -> target_unreachable/not_evaluated
   - host online + porta fechada -> success/not_detected
   - host online + porta aberta -> success/detected

3. Nuclei HTTP:
   - host inexistente -> target_unreachable/not_evaluated
   - host online sem 80/443/8080/8443 -> success/not_applicable
   - host com HTTP e sem match -> success/not_detected
   - host com match -> success/detected + evidence normalizada

4. Runtime:
   - alterar nuclei.exe -> Doctor acusa Runtime Integrity FAILED
   - remover templates -> Doctor acusa Templates unavailable

5. Backend/Runner:
   - queda temporária do backend -> Runner mantém retry e volta a consumir jobs.
