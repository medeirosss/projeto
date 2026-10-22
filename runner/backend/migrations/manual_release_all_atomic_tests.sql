-- Libera o catálogo para uso por admins sem alterar classificação de risco.
UPDATE atomic_tests
SET
    enabled = true,
    approved_for_lab = true,
    approved_for_execution = true,
    updated_at = now()
WHERE enabled = true;
