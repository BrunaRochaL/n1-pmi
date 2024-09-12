document.getElementById("checkUrl").addEventListener("click", function () {
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    const url = tabs[0].url;
    fetch("http://localhost:3000/analisar-url", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url }),
    })
      .then((response) => response.json())
      .then((data) => {
        document.getElementById("status").textContent =
          "Resultado: " + data.resultado;
      })
      .catch((error) => {
        console.error("Error:", error);
        document.getElementById("status").textContent =
          "Erro ao analisar a URL.";
      });
  });
});
