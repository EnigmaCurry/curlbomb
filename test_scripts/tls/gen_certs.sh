mkdir ca ca/certs ca/crl ca/newcerts ca/private
touch ca/index.txt
echo 1000 > ca/serial
mkdir ca/intermediate
mkdir ca/intermediate ca/intermediate/certs ca/intermediate/crl ca/intermediate/csr ca/intermediate/newcerts ca/intermediate/private
touch ca/intermediate/index.txt
echo 1000 > ca/intermediate/serial
echo 1000 > ca/intermediate/crlnumber
cp openssl.cnf ca/openssl.cnf
cp openssl-intermediate.cnf ca/intermediate/openssl.cnf


# Create an unencrypted CA key:
cd ca
openssl genrsa -out private/ca.key.pem 4096

# Create CA certificate (Press Enter several times to choose defaults):
openssl req -config openssl.cnf -key private/ca.key.pem -new -x509 -days 365000 -sha256 -extensions v3_ca -out certs/ca.cert.pem

openssl genrsa -out intermediate/private/intermediate.key.pem 4096

openssl req -config intermediate/openssl.cnf -new -sha256 -key intermediate/private/intermediate.key.pem -out intermediate/csr/intermediate.csr.pem
openssl ca -config openssl.cnf -extensions v3_intermediate_ca -days 365000 -notext -md sha256 -in intermediate/csr/intermediate.csr.pem -out intermediate/certs/intermediate.cert.pem

cat intermediate/private/intermediate.key.pem intermediate/certs/intermediate.cert.pem certs/ca.cert.pem > ../test.pem
cat intermediate/certs/intermediate.cert.pem certs/ca.cert.pem > ../test_chain.pem
