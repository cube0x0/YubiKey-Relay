import { showError, showSuccess, hideAlerts } from "./alert.mjs";


export async function authenticate(otp_code) {
  try {
    let response = await fetch("/api/authenticate", {
      method: "POST",
      body: JSON.stringify({ otp_code }),
      redirect: "follow",
      headers: { "Content-Type": "application/json" },
    });
    if (!response.ok) {
      return showError("failed to make request");
    }
    else
    { 
      hideAlerts();
      showSuccess("Success!");
    }
  } catch (e) {
    showError(e);
  }
}