async function executeAtomicLab(atomicTestId) {
  const runnerInput = document.querySelector("#atomicRunnerId");
  const runnerId = runnerInput ? runnerInput.value.trim() : "runner-win-01";

  const confirmation = confirm(
    "Executar Atomic REAL em LAB no Runner selecionado?\n\n" +
    "A execução ocorrerá LOCALMENTE no Runner, não no campo Target.\n" +
    "Somente prossiga se o teste estiver aprovado e for low-risk."
  );

  if (!confirmation) return;

  const response = await fetch(`/api/validations/atomic/tests/${atomicTestId}/execute-lab`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({runner_id: runnerId})
  });

  const data = await response.json();

  const output = document.querySelector("#atomicExecutionOutput");
  if (output) {
    output.textContent = JSON.stringify(data, null, 2);
  }

  if (!response.ok || data.blocked) {
    alert("Execução bloqueada. Veja os detalhes no painel.");
    return;
  }

  alert("Job de execução LAB enviado ao Runner.");

  if (typeof refreshAtomicExecutions === "function") {
    refreshAtomicExecutions();
  }
}


function renderAtomicExecutionEvidence(executionOrJob) {
  const result = executionOrJob.result || executionOrJob.payload || {};

  const command = result.command || executionOrJob.command_preview || "";
  const stdout = result.stdout || "";
  const stderr = result.stderr || "";
  const exitCode = result.exit_code ?? "";
  const executedRealTest = result.executed_real_test === true;

  return `
    <details class="atomic-evidence">
      <summary>Evidência</summary>
      <div><b>Execução real:</b> ${executedRealTest ? "SIM" : "NÃO"}</div>
      <div><b>Exit code:</b> ${exitCode}</div>
      <div><b>Comando:</b></div>
      <pre>${escapeHtml(command)}</pre>
      <div><b>STDOUT:</b></div>
      <pre>${escapeHtml(stdout)}</pre>
      <div><b>STDERR:</b></div>
      <pre>${escapeHtml(stderr)}</pre>
    </details>
  `;
}


function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}