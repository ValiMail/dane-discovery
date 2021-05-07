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
LOCAL_CA_DIR="${CRYPTO_DIR}/local_ca"
DEV_DIR="${CRYPTO_DIR}/device"

# General device info
RSA_DEVICE_SERIAL="rsa"
DEVICE_MODEL="air-quality-sensor"
ECC_DEVICE_SERIAL="ecc"

# Building DIDN-IDs for devices
RSA_DIDN_ID="${RSA_DEVICE_SERIAL}.${DEVICE_MODEL}._device.${LOCAL_DOMAIN}"
ECC_DIDN_ID="${ECC_DEVICE_SERIAL}.${DEVICE_MODEL}._device.${LOCAL_DOMAIN}"

# Specific file paths

## Local CA
LOCAL_CA_KEY="${LOCAL_CA_DIR}/ca.example.net.key.pem"
LOCAL_CA_CERT="${LOCAL_CA_DIR}/ca.example.net.cert.pem"

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

mkdir -p ${LOCAL_CA_DIR}/demoCA/
echo "05" > ${LOCAL_CA_DIR}/demoCA/serial 

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
    ${LOCAL_CA_DIR} \
    ${DEV_DIR} \
    ${LOCAL_CA_DIR}/demoCA/

##############
# Create local
# CA
##############
cd ${LOCAL_CA_DIR}
openssl genrsa \
    -out ${LOCAL_CA_KEY} \
    4096
openssl req \
    -key ${LOCAL_CA_KEY} \
    -new \
    -x509 \
    -days 7300 \
    -sha256 \
    -subj "/C=US/ST=CA/O=Example Networks/CN=Example Networks CA" \
    -out ${LOCAL_CA_CERT}
openssl x509 -noout -text -in ${LOCAL_CA_CERT}
touch ${LOCAL_CA_DIR}/demoCA/index.txt
touch ${LOCAL_CA_DIR}/demoCA/index.txt.attr

##############
# Create local
# device RSA 2048
##############
cd ${LOCAL_CA_DIR}
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
  -cert ${LOCAL_CA_CERT} \
  -keyfile ${LOCAL_CA_KEY} \
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

##############
# Create local
# device ECC p256
##############
cd ${LOCAL_CA_DIR}
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
  -cert ${LOCAL_CA_CERT} \
  -keyfile ${LOCAL_CA_KEY} \
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
# cat ${RSA_SSL_CONFIG}
##############
# Copy files
# for export
##############
cp -t ${CRYPTO_EXPORT_PATH} \
    ${LOCAL_CA_KEY} \
    ${LOCAL_CA_CERT} \
    ${RSA_DEV_KEY} \
    ${RSA_DEV_CERT_DER} \
    ${RSA_DEV_CSR} \
    ${RSA_DEV_CERT} \
    ${ECC_DEV_KEY} \
    ${ECC_DEV_CERT_DER} \
    ${ECC_DEV_CSR} \
    ${ECC_DEV_CERT}

##############
# Print results
##############
echo "######## RESULTING FILES ##########"
ls -lah ${CRYPTO_EXPORT_PATH}
echo "Crypto builder phase complete!"

echo "####### CERTIFICATE METADATA #######"
echo "## CA certificate:"
openssl x509 -text -noout -in ${LOCAL_CA_CERT}
echo "## Entity certificates:"
echo "#################### LOCAL RSA DEV CERTIFICATE ####################"
openssl x509 -noout -text -in ${RSA_DEV_CERT}

echo "#################### LOCAL RSA DEV CERTIFICATE ####################"
openssl x509 -noout -text -in ${ECC_DEV_CERT}

echo "### END CRYPTO GENERATION PROCESS ###"