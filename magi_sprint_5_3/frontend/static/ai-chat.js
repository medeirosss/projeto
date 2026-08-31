(function () {
  function ready(fn) {
    if (document.readyState !== "loading") fn();
    else document.addEventListener("DOMContentLoaded", fn);
  }

  ready(function () {
    if (document.getElementById("ai-chat-button")) return;

    const button = document.createElement("button");
    button.id = "ai-chat-button";
    button.innerHTML = "🤖";
    button.title = "Assistente Magi";

    const box = document.createElement("div");
    box.id = "ai-chat-box";
    box.className = "ai-chat-hidden";
    box.innerHTML = `
      <div class="ai-chat-header">
        <span>Assistente Magi</span>
        <button id="ai-chat-close" type="button">×</button>
      </div>
      <div id="ai-chat-messages">
        <div class="ai-chat-message ai-chat-bot">
          <strong>Magi IA:</strong><br>
          Olá! Posso responder consultas gerais sobre segurança, alertas, MITRE, NIST, CVEs e playbooks.
        </div>
      </div>
      <div class="ai-chat-input">
        <input id="ai-chat-text" type="text" placeholder="Digite sua pergunta..." autocomplete="off" />
        <button id="ai-chat-send" type="button">Enviar</button>
      </div>
    `;

    document.body.appendChild(button);
    document.body.appendChild(box);

    const close = document.getElementById("ai-chat-close");
    const send = document.getElementById("ai-chat-send");
    const input = document.getElementById("ai-chat-text");
    const messages = document.getElementById("ai-chat-messages");

    button.addEventListener("click", function () {
      box.classList.toggle("ai-chat-hidden");
      if (!box.classList.contains("ai-chat-hidden")) input.focus();
    });

    close.addEventListener("click", function () {
      box.classList.add("ai-chat-hidden");
    });

    function escapeHtml(text) {
      const div = document.createElement("div");
      div.textContent = text;
      return div.innerHTML;
    }

    function addMessage(author, text, cssClass) {
      const div = document.createElement("div");
      div.className = "ai-chat-message " + cssClass;
      div.innerHTML = `<strong>${author}:</strong><br>${escapeHtml(text).replace(/\n/g, "<br>")}`;
      messages.appendChild(div);
      messages.scrollTop = messages.scrollHeight;
      return div;
    }

    async function sendMessage() {
      const text = input.value.trim();
      if (!text) return;

      addMessage("Você", text, "ai-chat-user");
      input.value = "";

      const loading = addMessage("Magi IA", "Consultando...", "ai-chat-bot");
      send.disabled = true;
      input.disabled = true;

      try {
        const response = await fetch("/api/ai/chat", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message: text }),
        });

        const data = await response.json();
        const answer = data.answer || data.detail || "Sem resposta da IA.";
        loading.innerHTML = `<strong>Magi IA:</strong><br>${escapeHtml(answer).replace(/\n/g, "<br>")}`;
      } catch (error) {
        loading.innerHTML = "<strong>Magi IA:</strong><br>Erro ao consultar a IA.";
      } finally {
        send.disabled = false;
        input.disabled = false;
        input.focus();
      }
    }

    send.addEventListener("click", sendMessage);
    input.addEventListener("keydown", function (event) {
      if (event.key === "Enter") sendMessage();
    });
  });
})();
