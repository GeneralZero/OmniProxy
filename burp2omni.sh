#!/usr/bin/env bash

set -e

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <Burp_DER_Certificate> <Burp_DER_Private_key>"
    exit 1
fi

if ! type "openssl" > /dev/null; then
    echo "Could not find Openssl"
    exit 1
fi

openssl rsa -in $2 -out ca_key.pem
openssl x509 -in $1 -inform der -out ca_crt.pem
cat ca_key.pem ca_crt.pem > ca.pem

echo "Cert and Key are converted."
echo "Can now be used with \"-c ca.pem\" "
