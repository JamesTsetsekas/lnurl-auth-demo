const statusElement = document.querySelector("#login-status");

async function checkLoginStatus() {
  try {
    const response = await fetch("/auth/status", {
      cache: "no-store",
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    });
    const result = await response.json();

    if (result.status === "authenticated") {
      if (statusElement) statusElement.textContent = "Signature verified. Finishing login…";
      window.location.replace("/success");
      return;
    }
    if (result.status === "expired" || result.status === "anonymous") {
      if (statusElement) statusElement.textContent = "Challenge expired. Creating a fresh one…";
      window.location.reload();
      return;
    }
  } catch {
    if (statusElement) statusElement.textContent = "Connection interrupted. Retrying…";
  }

  window.setTimeout(checkLoginStatus, 1500);
}

window.setTimeout(checkLoginStatus, 900);
