###################################
# This phase creates all the certs
# and keys we'll use in a later
# phase, for testing the ca_app
# library.
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
LOCAL_DEV_DIR="${CRYPTO_DIR}/local_dev"

# General device info
DEVICE_SERIAL="abc123"
DEVICE_MODEL="air-quality-sensor"

# Building DIDN-IDs for devices
L_DIDN_ID="${DEVICE_SERIAL}.${DEVICE_MODEL}._device.${LOCAL_DOMAIN}"

# Specific file paths

## Local CA
LOCAL_CA_KEY="${LOCAL_CA_DIR}/ca.example.net.key.pem"
LOCAL_CA_CERT="${LOCAL_CA_DIR}/ca.example.net.cert.pem"

## Local Dev
LOCAL_DEV_KEY="${LOCAL_DEV_DIR}/${L_DIDN_ID}.key.pem"
LOCAL_DEV_CSR="${LOCAL_DEV_DIR}/${L_DIDN_ID}.csr.pem"
LOCAL_DEV_CERT="${LOCAL_DEV_DIR}/${L_DIDN_ID}.cert.pem"

##############
# Install OpenSSL
##############
apt-get update && \
    apt-get install -y \
    openssl \
    tree

##############
# Fix OpenSSL
# config for
# CA signing
##############
# RUN cat /etc/ssl/openssl.cnf | \
#    sed \
#        -e 's/^\[ usr_cert \]/[ usr_cert ]\n\nsubjectAltName = DNS:copy/g' \
#        -e 's/^\[ v3_req \]/[ v3_req ]\n\nsubjectAltName = DNS:copy/g' \
#  | tee /usr/lib/ssl/openssl.cnf
cat /usr/lib/ssl/openssl.cnf



##############
# Create dirs
##############
mkdir -p \
    ${CRYPTO_EXPORT_PATH} \
    ${CRYPTO_DIR} \
    ${LOCAL_CA_DIR} \
    ${LOCAL_DEV_DIR} \
    ${LOCAL_CA_DIR}/demoCA/

##############
# Drop dev
# conf files
##############
cp /usr/lib/ssl/openssl.cnf ${LOCAL_CA_DIR}/san.cnf
echo "[ SAN ]\nsubjectAltName = DNS:${L_DIDN_ID}" >> ${LOCAL_CA_DIR}/san.cnf


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
# device
##############
cd ${LOCAL_CA_DIR}
openssl genrsa \
    -out ${LOCAL_DEV_KEY} \
    2048
openssl req \
    -key ${LOCAL_DEV_KEY} \
    -new \
    -sha256 \
    -subj "/C=US/ST=CA/O=Example Networks/CN=${L_DIDN_ID}" \
    -addext "subjectAltName = DNS:${L_DIDN_ID}" \
    -out ${LOCAL_DEV_CSR}
echo "#################### LOCAL DEV CSR ####################"
openssl req -noout -text -in ${LOCAL_DEV_CSR}
openssl ca \
    -extensions usr_cert \
    -extensions v3_req \
    -extensions SAN \
    -days 375 \
    -notext \
    -md sha256 \
    -keyfile ${LOCAL_CA_KEY} \
    -cert ${LOCAL_CA_CERT} \
    -outdir ${LOCAL_DEV_DIR} \
    -create_serial \
    -extfile ${LOCAL_CA_DIR}/san.cnf \
    -batch \
    -in ${LOCAL_DEV_CSR} \
    -out ${LOCAL_DEV_CERT}
echo "#################### LOCAL DEV CERTIFICATE ####################"
openssl x509 -noout -text -in ${LOCAL_DEV_CERT}

##############
# Copy files
# for export
##############
cp ${LOCAL_CA_KEY} ${CRYPTO_EXPORT_PATH}
cp ${LOCAL_CA_CERT} ${CRYPTO_EXPORT_PATH}
cp ${LOCAL_DEV_KEY} ${CRYPTO_EXPORT_PATH}
cp ${LOCAL_DEV_CSR} ${CRYPTO_EXPORT_PATH}
cp ${LOCAL_DEV_CERT} ${CRYPTO_EXPORT_PATH}

##############
# Print results
##############
echo "######## RESULTING FILES ##########"
ls -lah ${CRYPTO_EXPORT_PATH}
echo "Crypto builder phase complete!"
