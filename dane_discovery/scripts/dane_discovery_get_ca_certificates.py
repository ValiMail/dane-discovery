"""Download all PKIX-CD CA certificates for an identity."""
import argparse
import os

from dane_discovery.dane import DANE
from dane_discovery.pki import PKI
from dane_discovery.identity import Identity



parser = argparse.ArgumentParser(description="Retrieve and store all CA certificates required for PKIX-CD authentication of an identity.")
parser.add_argument("--output_path", dest="out_path", required=True, help="Output path for certificate bundle")
parser.add_argument("--separate_files", dest="separate_files", required=False, 
                    action="store_true", help=("This will use --output_path as"
                        "a directory for writing individual certificate files. "
                        "Individual CA certificate files will be named AUTHORITY_HOSTNAME-CA-subjectKeyID.crt.pem"))
parser.add_argument("--identity_name", dest="dnsname", required=True, help="Identity DNS name")
parser.set_defaults(separate_files=False)

def main():
    """Wrap functionality provided by Identity.get_all_certificates()"""
    # Parse args
    args = parser.parse_args()
    # Get PKIX-CD certs from DNS
    identity = Identity(args.dnsname)
    ee_certs = identity.get_all_certificates(filters=["PKIX-CD"])
    # Get the CA certificates for the EE certs
    certs = {}
    for _, ee_cert_pem in ee_certs.items():
        try:
            identity = Identity(args.dnsname)
            ca_pem = identity.get_pkix_cd_trust_chain(ee_cert_pem)["root"]
        except ValueError as err:
            print(err)
            continue
        except KeyError as err:
            print("Key Error! Are we able to obtain the root CA certificate? {}".format(err))
            continue
        authority_hostname = DANE.generate_authority_hostname(args.dnsname)
        ca_cert_skid = PKI.get_subject_key_id_from_certificate(ca_pem)
        ca_cert_name = "{}-CA-{}".format(authority_hostname, ca_cert_skid.replace("-", ""))
        certs[ca_cert_name] = ca_pem
    # Write out files
    if args.separate_files:
        write_individual_certs(certs, args.out_path)
    else:
        write_cert_bundle(certs, args.out_path)


def write_individual_certs(certs, out_path):
    prepped = [(os.path.join(out_path, "{}.crt.pem".format(name)), contents) 
               for name, contents in certs.items()]
    for item in prepped:
        write_file(*item)


def write_cert_bundle(certs, out_path):
    just_certs = [y for _, y in certs.items()]
    contents = b"\n".join(just_certs)
    write_file(out_path, contents)


def write_file(file_path, contents):
    """Write a string to a file."""
    with open(file_path, "wb") as f_obj:
        f_obj.write(contents)


if __name__ == "__main__":
    main()