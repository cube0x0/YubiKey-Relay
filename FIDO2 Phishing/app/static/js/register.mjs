import * as CBOR from "./cbor.mjs";
import { showError, showSuccess, hideAlerts } from "./alert.mjs";

export default async function (userId, userName, displayName) {
  console.log(`Registering with name=${userName}, id=${userId}, displayName=${displayName}`);

  hideAlerts();

  try {

    let response = await fetch("/api/register", {
      method: "POST",
      body: JSON.stringify({userName, userId, displayName}),
      redirect: "follow",
      headers: {"Content-Type": "application/json"},
    });
    const options = CBOR.decode(await response.arrayBuffer());

    // prompt the user to use the security device
    const attestation = await navigator.credentials.create(options);

    // send the attestation to the server
    response = await fetch("/api/register/complete", {
      method: "POST",
      redirect: "follow",
      headers: {"Content-Type": "application/cbor"},
      body: CBOR.encode({
        userId,
        attestationObject: new Uint8Array(attestation.response.attestationObject),
        clientDataJSON: new Uint8Array(attestation.response.clientDataJSON),
      }),
    });

    if (response.ok) {
      showSuccess("Public key registered!")
      console.log("registered ok!", response);
    } else {
      console.error(response);
    }
  } catch (e) {
    showError(e);
  }
}