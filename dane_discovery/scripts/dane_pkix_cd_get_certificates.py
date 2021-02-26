"""Download all PKIX-CD certificates for an identity."""
import argparse
import os
import sys

from dane_discovery.dane import DANE
from dane_discovery.identity import Identity



def main():
    """Wrap functionality provided by Identity.get_all_pkix_cd_certificates()"""
    # Parse args
    parser = argparse.ArgumentParser("Retrieve and store all PKIX-CD certificates for an identity.")
    parser.add_argument("--output_path", dest="out_path", required=True, help="Output path for certificate bundle")
    parser.add_argument("--separate_files", dest="separate_files", required=False, 
                        action="store_true", help=("This will use --output_path as"
                            "a directory for writing individual certificate files."))
    parser.add_argument("--identity_name", dest="dnsname", required=True, help="Identity DNS name")
    parser.set_defaults(separate_files=False)
    args = parser.parse_args()
    # Get PKIX-CD certs from DNS
    identity = Identity(args.dnsname)
    certs = identity.get_all_pkix_cd_certificates()
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
    contents = "\n".join(just_certs)
    write_file(out_path, contents)


def write_file(file_path, contents):
    """Write a string to a file."""
    with open(file_path, "wb") as f_obj:
        f_obj.write(contents)


if __name__ == "__main__":
    main()