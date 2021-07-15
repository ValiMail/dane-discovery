set -xe
###################################
# This phase creates all the certs
# and keys we'll use in a later
# phase.
###################################

##############
# Set env vars
##############
# Domains
LOCAL_DOMAIN="example.net"

# Base paths
CRYPTO_EXPORT_PATH="${HOME}/export"
CRYPTO_DIR="${HOME}/crypto"
ROOT_CA_DIR="${CRYPTO_DIR}/root_ca"
INTERMEDIATE_CA_DIR="${CRYPTO_DIR}/intermediate_ca"
DEV_DIR="${CRYPTO_DIR}/device"

# General device info
RSA_DEVICE_SERIAL="rsa"
DEVICE_MODEL="air-quality-sensor"
ECC_DEVICE_SERIAL="ecc"

# Building DIDN-IDs for devices
RSA_DIDN_ID="${RSA_DEVICE_SERIAL}.${DEVICE_MODEL}._device.${LOCAL_DOMAIN}"
ECC_DIDN_ID="${ECC_DEVICE_SERIAL}.${DEVICE_MODEL}._device.${LOCAL_DOMAIN}"

# Specific file paths

## Local Root CA
ROOT_CA_KEY="${ROOT_CA_DIR}/rootca.example.net.key.pem"
ROOT_CA_CERT="${ROOT_CA_DIR}/rootca.example.net.cert.pem"
ROOT_CA_CSR="${ROOT_CA_DIR}/rootca.example.net.csr.pem"

## Local intermediate CA
INTERMEDIATE_CA_KEY="${INTERMEDIATE_CA_DIR}/intermediateca.example.net.key.pem"
INTERMEDIATE_CA_CERT="${INTERMEDIATE_CA_DIR}/intermediateca.example.net.cert.pem"
INTERMEDIATE_CA_CSR="${INTERMEDIATE_CA_DIR}/intermediateca.example.net.csr.pem"

## RSA Dev
RSA_DEV_KEY="${DEV_DIR}/${RSA_DIDN_ID}.key.pem"
RSA_DEV_CSR="${DEV_DIR}/${RSA_DIDN_ID}.csr.pem"
RSA_DEV_CERT="${DEV_DIR}/${RSA_DIDN_ID}.cert.pem"
RSA_DEV_CERT_DER="${DEV_DIR}/${RSA_DIDN_ID}.cert.der"

## ECC Dev
ECC_DEV_KEY="${DEV_DIR}/${ECC_DIDN_ID}.key.pem"
ECC_DEV_CSR="${DEV_DIR}/${ECC_DIDN_ID}.csr.pem"
ECC_DEV_CERT="${DEV_DIR}/${ECC_DIDN_ID}.cert.pem"
ECC_DEV_CERT_DER="${DEV_DIR}/${ECC_DIDN_ID}.cert.der"

# Signing configurations
RSA_SSL_CONFIG="${DEV_DIR}/${RSA_DIDN_ID}.conf"
ECC_SSL_CONFIG="${DEV_DIR}/${ECC_DIDN_ID}.conf"

mkdir -p ${ROOT_CA_DIR}/demoCA/
echo "05" > ${ROOT_CA_DIR}/demoCA/serial 

mkdir -p ${INTERMEDIATE_CA_DIR}/demoCA/
echo "05" > ${INTERMEDIATE_CA_DIR}/demoCA/serial 

##############
# Install OpenSSL
##############
apt-get update && \
    apt-get install -y \
    openssl \
    tree

sudo cp ssl.cnf /usr/lib/ssl/openssl.cnf
cat /usr/lib/ssl/openssl.cnf

##############
# Create dirs
##############
mkdir -p \
    ${CRYPTO_EXPORT_PATH} \
    ${CRYPTO_DIR} \
    ${DEV_DIR} \
    ${ROOT_CA_DIR}/demoCA/ \
    ${ROOT_CA_DIR}/demoCA/newcerts/ \
    ${INTERMEDIATE_CA_DIR}/demoCA/ \
    ${INTERMEDIATE_CA_DIR}/demoCA/newcerts/

##############
# Create self-signed
# root CA
##############
echo "Create root CA certificate"
touch ${ROOT_CA_DIR}/demoCA/index.txt
touch ${ROOT_CA_DIR}/demoCA/index.txt.attr
cd ${ROOT_CA_DIR}
openssl req \
    -new \
    -keyout ${ROOT_CA_KEY} \
    -nodes \
    -days 7300 \
    -sha256 \
    -subj "/C=US/ST=CA/O=Example Networks/CN=Example Networks Root CA" \
    -reqexts v3_ca_req \
    -out ${ROOT_CA_CSR}

cat ${ROOT_CA_CSR}

openssl ca \
    -selfsign \
    -keyfile ${ROOT_CA_KEY} \
    -in ${ROOT_CA_CSR} \
    -out ${ROOT_CA_CERT} \
    -name CA_default \
    -extensions v3_ca \
    -batch \
    -verbose 

openssl x509 -noout -text -in ${ROOT_CA_CERT}
openssl x509 -noout -text -in ${ROOT_CA_CERT} | grep "CA:FALSE" && echo "NOT A CA CERTIFICATE" && exit 1

##############
# Create 
# intermediate CA
##############
echo "Create intermediate CA certificate"
touch ${INTERMEDIATE_CA_DIR}/demoCA/index.txt
touch ${INTERMEDIATE_CA_DIR}/demoCA/index.txt.attr
cd ${INTERMEDIATE_CA_DIR}
openssl req \
    -new \
    -keyout ${INTERMEDIATE_CA_KEY} \
    -nodes \
    -days 7300 \
    -sha256 \
    -subj "/C=US/ST=CA/O=Example Networks/CN=Example Networks Intermediate CA" \
    -reqexts v3_ca_req \
    -out ${INTERMEDIATE_CA_CSR}

cat ${INTERMEDIATE_CA_CSR}

openssl ca \
    -keyfile ${ROOT_CA_KEY} \
    -cert ${ROOT_CA_CERT} \
    -in ${INTERMEDIATE_CA_CSR} \
    -out ${INTERMEDIATE_CA_CERT} \
    -name CA_default \
    -batch \
    -extensions v3_ca \
    -verbose

echo "Check intermediate cert against root cert"
cat ${INTERMEDIATE_CA_CERT}
openssl x509 -noout -text -in ${INTERMEDIATE_CA_CERT}
openssl x509 -noout -text -in ${INTERMEDIATE_CA_CERT} | grep "CA:FALSE" && echo "NOT A CA CERTIFICATE" && exit 1
openssl verify -verbose -show_chain -CAfile ${ROOT_CA_CERT} ${INTERMEDIATE_CA_CERT}

##############
# Create local
# device RSA 2048
##############
cd ${INTERMEDIATE_CA_DIR}
# Generate private key
openssl genrsa \
    -out ${RSA_DEV_KEY} \
    2048
# Generate CSR
openssl req \
    -key ${RSA_DEV_KEY} \
    -new \
    -sha256 \
    -subj "/C=US/ST=CA/O=Example Networks/CN=${RSA_DIDN_ID}" \
    -addext "subjectAltName = DNS:${RSA_DIDN_ID}" \
    -addext "keyUsage = nonRepudiation, digitalSignature, keyEncipherment" \
    -out ${RSA_DEV_CSR}

echo "#################### LOCAL RSA DEV CSR ####################"
openssl req -noout -text -in ${RSA_DEV_CSR}
# Add the SAN config to the end of the openssl conf file.
cp /usr/lib/ssl/openssl.cnf ${RSA_SSL_CONFIG}
echo -e "\n[alternate_names]" >> ${RSA_SSL_CONFIG}
echo -e "DNS.1 = ${RSA_DIDN_ID}\n" >> ${RSA_SSL_CONFIG}
# Accommodate the default behavior of openssl ca.
openssl ca \
  -config ${RSA_SSL_CONFIG} \
  -days 375 \
  -in ${RSA_DEV_CSR} \
  -cert ${INTERMEDIATE_CA_CERT} \
  -keyfile ${INTERMEDIATE_CA_KEY} \
  -outdir /tmp/ \
  -extensions usr_cert \
  -extfile ${RSA_SSL_CONFIG} \
  -batch \
  -out ${RSA_DEV_CERT}
# Generate DER of certificate
openssl x509 \
    -in ${RSA_DEV_CERT} \
    -out ${RSA_DEV_CERT_DER} \
    -outform DER

echo "Check entity cert chain to root cert"
cat ${RSA_DEV_CERT}
openssl x509 -noout -text -in ${RSA_DEV_CERT}
openssl verify -verbose -show_chain -CAfile ${ROOT_CA_CERT} -untrusted ${INTERMEDIATE_CA_CERT} ${RSA_DEV_CERT}

##############
# Create local
# device ECC p256
##############
cd ${INTERMEDIATE_CA_DIR}
# Generate private key
openssl ecparam -genkey \
    -name prime256v1 \
    -out ${ECC_DEV_KEY} 
# Generate CSR
openssl req \
    -key ${ECC_DEV_KEY} \
    -new \
    -sha256 \
    -subj "/C=US/ST=CA/O=Example Networks/CN=${ECC_DIDN_ID}" \
    -addext "subjectAltName = DNS:${ECC_DIDN_ID}" \
    -addext "keyUsage = nonRepudiation, digitalSignature, keyEncipherment" \
    -out ${ECC_DEV_CSR}

echo "#################### LOCAL ECC DEV CSR ####################"
openssl req -noout -text -in ${ECC_DEV_CSR}
# Add the SAN config to the end of the openssl conf file.
cp /usr/lib/ssl/openssl.cnf ${ECC_SSL_CONFIG}
echo -e "\n[alternate_names]" >> ${ECC_SSL_CONFIG}
echo -e "DNS.1 = ${ECC_DIDN_ID}\n" >> ${ECC_SSL_CONFIG}
# Accommodate the default behavior of openssl ca.
openssl ca \
  -config ${ECC_SSL_CONFIG} \
  -days 375 \
  -in ${ECC_DEV_CSR} \
  -cert ${INTERMEDIATE_CA_CERT} \
  -keyfile ${INTERMEDIATE_CA_KEY} \
  -outdir /tmp/ \
  -extensions usr_cert \
  -extfile ${ECC_SSL_CONFIG} \
  -batch \
  -out ${ECC_DEV_CERT}
# Generate DER of certificate
openssl x509 \
    -in ${ECC_DEV_CERT} \
    -out ${ECC_DEV_CERT_DER} \
    -outform DER

echo "Check entity cert chain to root cert"
cat ${ECC_DEV_CERT}
openssl x509 -noout -text -in ${ECC_DEV_CERT}
openssl verify -verbose -show_chain -CAfile ${ROOT_CA_CERT} -untrusted ${INTERMEDIATE_CA_CERT} ${ECC_DEV_CERT}

##############
# Copy files
# for export
##############
cp -t ${CRYPTO_EXPORT_PATH} \
    ${ROOT_CA_KEY} \
    ${ROOT_CA_CERT} \
    ${INTERMEDIATE_CA_KEY} \
    ${INTERMEDIATE_CA_CERT} \
    ${RSA_DEV_KEY} \
    ${RSA_DEV_CERT_DER} \
    ${RSA_DEV_CSR} \
    ${RSA_DEV_CERT} \
    ${ECC_DEV_KEY} \
    ${ECC_DEV_CERT_DER} \
    ${ECC_DEV_CSR} \
    ${ECC_DEV_CERT}

# cat ${INTERMEDIATE_CA_CERT} ${ROOT_CA_CERT} > ${CRYPTO_EXPORT_PATH}/chain.pem
# cat ${CRYPTO_EXPORT_PATH}/chain.pem
# cat ${RSA_DEV_CERT}



##############
# Print results
##############
echo "######## RESULTING FILES ##########"
ls -lah ${CRYPTO_EXPORT_PATH}
echo "Crypto builder phase complete!"

echo "####### CERTIFICATE METADATA #######"
echo "## Root CA certificate:"
openssl x509 -text -noout -in ${ROOT_CA_CERT}
echo "## Intermediate CA certificate:"
openssl x509 -text -noout -in ${INTERMEDIATE_CA_CERT}
echo "## Entity certificates:"
echo "#################### LOCAL RSA DEV CERTIFICATE ####################"
openssl x509 -noout -text -in ${RSA_DEV_CERT}

echo "#################### LOCAL RSA DEV CERTIFICATE ####################"
openssl x509 -noout -text -in ${ECC_DEV_CERT}

echo "### END CRYPTO GENERATION PROCESS ###"
