import { showError, showSuccess, hideAlerts } from "./alert.mjs";
import * as CBOR from "./cbor.mjs";


export async function authenticate() {
  try {
    //const bb = null;
    //let str = 'data:application/octet-stream;base64,2vxM+x5aBvnS4HCJ16kXeSbuidibRHNO9TZkBZ98SmY=';
    //fetch(str)
    //  .then(b => b.arrayBuffer())
    //  .then(buff => console.log( new Int8Array(buff) /* just for a view purpose */ ))
    //  .catch(e => console.log(e))
    //var options = {
    //  rpId: "demo.yubico.com",
    //  challenge: new Uint8Array([-38,-4,76,-5,30,90,6,-7,-46,-32,112,-119,-41,-87,23,121,38,-18,-119,-40,-101,68,115,78,-11,54,100,5,-97,124,74,102])
    //};
    //
    //const assertion = navigator.credentials.get({"mediation":"silent", "publicKey": options })
    //    .then(function (credentialInfoAssertion) {
    //      //something
    //}).catch(function (err) {
    //     console.error(err);
    //});



    let response = await fetch("/api/authenticate", {
      method: "POST",
      redirect: "follow",
      headers: { "Content-Type": "application/json" },
    });
    if (!response.ok) {
      return showError("failed to make request");
    }

    const options = CBOR.decode(await response.arrayBuffer());
    const assertion = await navigator.credentials.get(options);
    
    response = await fetch("/api/authenticate/forward", {
      method: "POST",
      headers: {"Content-Type": "application/cbor"},
      body: CBOR.encode({
        credentialId: new Uint8Array(assertion.rawId),
        authenticatorData: new Uint8Array(assertion.response.authenticatorData),
        clientDataJSON: new Uint8Array(assertion.response.clientDataJSON),
        signature: new Uint8Array(assertion.response.signature),
        userHandle: new Uint8Array(assertion.response.userHandle),
      })
    });

    if (response.ok) {
      hideAlerts();
      showSuccess("Success!");
    }
  } catch (e) {
    showError(e);
  }
}