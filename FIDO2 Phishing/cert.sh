openssl genrsa -des3 -out app/yubico-ca-key.pem 2048
openssl req -x509 -new -nodes -key app/yubico-ca-key.pem -sha256 -days 1825 -out app/yubico-ca.pem
openssl req -CA yubico-ca.pem -CAkey yubico-ca-key.pem -config cert.config -new -x509 -newkey rsa:2048 -nodes -keyout app/yubico-key.pem -days 365 -out app/yubico.pem