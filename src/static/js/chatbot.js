// Mostrar y ocultar la ventana del chatbot
document.getElementById("chatbotIcon").addEventListener("click", function () {
  document.getElementById("chatbotWindow").style.display = "flex";
});

document.getElementById("closeChatbot").addEventListener("click", function () {
  document.getElementById("chatbotWindow").style.display = "none";
});

// Enviar mensaje al presionar el botón
document
  .getElementById("sendChatbotMessage")
  .addEventListener("click", sendMessage);

// Enviar mensaje al presionar Enter
document
  .getElementById("chatbotInput")
  .addEventListener("keypress", function (e) {
    if (e.key === "Enter") {
      sendMessage();
    }
  });

function sendMessage() {
  var input = document.getElementById("chatbotInput");
  var message = input.value.trim();
  if (message) {
    var messages = document.getElementById("chatbotMessages");

    // Agregar mensaje del usuario
    var userMessage = document.createElement("div");
    userMessage.className = "chatbot-user-message";
    userMessage.textContent = message;
    messages.appendChild(userMessage);

    // Limpiar el input
    input.value = "";

    // Desplazar hacia abajo
    messages.scrollTop = messages.scrollHeight;

    // Enviar el mensaje al backend
    fetch("/chatbot", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": csrfToken, // Usa la variable definida en el script
      },
      body: JSON.stringify({ message: message }),
    })
      .then((response) => {
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
      })
      .then((data) => {
        // Agregar respuesta del bot
        var botMessage = document.createElement("div");
        botMessage.className = "chatbot-bot-message";
        botMessage.textContent = data.reply;
        messages.appendChild(botMessage);

        // Desplazar hacia abajo
        messages.scrollTop = messages.scrollHeight;
      })
      .catch((error) => {
        console.error("Error:", error);
        var errorMessage = document.createElement("div");
        errorMessage.className = "chatbot-bot-message";
        errorMessage.textContent = "Lo siento, ha ocurrido un error.";
        messages.appendChild(errorMessage);

        // Desplazar hacia abajo
        messages.scrollTop = messages.scrollHeight;
      });
  }
}

// Función para obtener el valor de una cookie (para CSRF)
function getCookie(name) {
  let cookieValue = null;
  if (document.cookie && document.cookie !== "") {
    const cookies = document.cookie.split(";");
    for (let i = 0; i < cookies.length; i++) {
      const cookie = cookies[i].trim();
      // ¿La cookie comienza con el nombre que queremos?
      if (cookie.substring(0, name.length + 1) === name + "=") {
        cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
        break;
      }
    }
  }
  return cookieValue;
}
