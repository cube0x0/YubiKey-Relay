from selenium import webdriver
from seleniumrequests import Firefox
from seleniumrequests.request import RequestsSessionMixin
from selenium.webdriver.common.proxy import Proxy, ProxyType
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time, json, base64, sys, os

class MyCustomWebDriver(Firefox,RequestsSessionMixin):
    pass

if __name__ == "__main__":  
    browser_options = webdriver.FirefoxOptions()
    useragent = "Mozilla/5.0 (Linux; Android 8.0.0; Pixel 2 XL Build/OPD1.170816.004) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.87 Mobile Safari/537.36"
    browser_options.set_preference("general.useragent.override", useragent)
    browser_options.set_preference("dom.webnotifications.serviceworker.enabled", False)
    browser_options.set_preference("dom.webnotifications.enabled", False)
    browser = MyCustomWebDriver(options=browser_options)
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
    if len(cred_ids) == 0:
        cred_ids = None
    challenge = begin_resp['data']['publicKey']['challenge']
    challenge_urlsafe = base64.urlsafe_b64encode(base64.b64decode(challenge)).decode()
    clientData = base64.urlsafe_b64encode(
        '{{"challenge":"{0}","origin":"https://demo.yubico.com","type":"webauthn.get"}}'.format(challenge_urlsafe).encode()
    ).decode()
    rpId = begin_resp['data']['publicKey']['rpId']
    userVerification = begin_resp['data']['publicKey']['userVerification']
    timeout = begin_resp['data']['publicKey']['timeout']

    assertion_input = {
        "AllowList":cred_ids,
        "RelyingPartyId":rpId,
        "ClientData":clientData,
        
        "timeout":timeout,
        "userVerification":userVerification,
        "challenge":challenge
    }

    print("[*] assertion:         {0}".format(json.dumps(assertion_input)))
    print("[*] base64 assertion:  {0}".format(base64.b64encode(json.dumps(assertion_input).encode()).decode()))

    #get data from yubikey
    assertion_output = input("enter assertion output: ")
    assertion_output = base64.b64decode(assertion_output).decode()
    assertion_output = json.loads(assertion_output)
    #print(assertion_output)
    authenticatorData = assertion_output["authenticatorData"]
    signature = assertion_output["signature"]
    cred_id = assertion_output["cred_id"]

    final_data = {
        "requestId":req_id,
        "assertion":
        {
            "credentialId":cred_id,
            "authenticatorData":authenticatorData,
            "clientDataJSON": clientData,
            "signature":signature
        },
        "namespace":"playground"
    }
    if "uuid" in begin_data.keys():
        final_data["uuid"] = begin_data["uuid"]
    if assertion_output["userHandle"] != "":
        final_data["assertion"]["userHandle"] = assertion_output["userHandle"]
    
    response = browser.request('POST', 'https://demo.yubico.com/api/v1/auth/webauthn/authenticate-finish', json=final_data)
    final_resp = response.json()
    if final_resp['status'] == 'success':
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