// MAGI - correção do botão Executar LAB
// Ajuste este código no validations.js onde hoje o botão chama a execução usando apenas test.id.

function getSelectedRunnerId() {
  const select = document.getElementById("runnerSelect") || document.getElementById("runner_id");
  return select ? select.value : window.selectedRunnerId;
}

async function executeAtomicLab(test) {
  const runnerId = getSelectedRunnerId();

  if (!runnerId) {
    alert("Selecione um runner antes de executar o LAB.");
    return;
  }

  const atomicTestNumber = Number(
    test.atomic_test_number ?? test.test_number ?? test.atomicNumber
  );

  const techniqueId = test.technique_id ?? test.techniqueId;

  if (!techniqueId || !atomicTestNumber) {
    console.error("Teste sem technique_id ou atomic_test_number:", test);
    alert("Teste inválido: technique_id ou atomic_test_number ausente.");
    return;
  }

  const payload = {
    runner_id: runnerId,
    technique_id: techniqueId,
    atomic_test_number: atomicTestNumber,
  };

  console.log("EXECUTE LAB payload:", payload);

  const resp = await fetch("/api/validations/lab/execute", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  let data = {};
  try {
    data = await resp.json();
  } catch (e) {
    data = { detail: await resp.text() };
  }

  console.log("EXECUTE LAB response:", data);

  if (!resp.ok) {
    alert(data.detail || "Erro ao executar LAB.");
    return;
  }

  alert("Execução enviada para o runner.");

  if (typeof loadValidationExecutions === "function") {
    await loadValidationExecutions();
  }
}

// Exemplo correto ao renderizar botão:
// button.onclick = () => executeAtomicLab(test);
// Não usar: executeAtomicLab(test.id)
