#!/usr/bin/env bash
set -euo pipefail

# Create an OpenSSL SAN config for the proxy cert (includes DNS localhost and the proxy IP)
cat > san.cnf <<EOF
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
[ req_distinguished_name ]
[ v3_req ]
subjectAltName = @alt_names
[ alt_names ]
DNS.1 = localhost
IP.1  = 10.248.100.11
EOF

# Generate CA (EC P-256)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out ca-key.pem
openssl req -x509 -new -key ca-key.pem -days 3650 -sha256 -subj "/CN=connect-ip-rust-scion CA" -out ca-cert.pem

# Generate proxy key and CSR
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out proxy-key.pem
openssl req -new -key proxy-key.pem -subj "/CN=localhost" -out proxy.csr.pem

# Sign proxy CSR with CA and include SANs
openssl x509 -req -in proxy.csr.pem -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
  -out proxy-cert.pem -days 825 -sha256 -extfile san.cnf -extensions v3_req

# Generate client key and CSR
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out client-key.pem
openssl req -new -key client-key.pem -subj "/CN=client" -out client.csr.pem

# Sign client CSR with CA
openssl x509 -req -in client.csr.pem -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
  -out client-cert.pem -days 825 -sha256

echo "Certificates and keys generated."