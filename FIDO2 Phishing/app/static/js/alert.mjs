export function showSuccess(message) {
  showAlert("alert-success", message);
}

export function showError(message) {
  showAlert("alert-error", message);
}

export function hideAlerts() {
  document.getElementById("alert-success").classList.add("visually-hidden");
  document.getElementById("alert-error").classList.add("visually-hidden");
}

function showAlert(elementId, message) {
  const alert = document.getElementById(elementId);
  alert.innerText = message;
  alert.classList.remove("visually-hidden");
}