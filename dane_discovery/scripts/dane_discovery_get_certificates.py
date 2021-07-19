"""Download all PKIX-CD certificates for an identity."""
import argparse
import os

from dane_discovery.identity import Identity



parser = argparse.ArgumentParser(description=("Retrieve, authenticate, and store all certificates for a DANE identity.\n"
                                 "Default behavior retrieves and authenticates all available entity certificates."
                                 "Adding filters for specific types (--pkix-cd, for instance) limits output to those types."))
parser.add_argument("--output_path", dest="out_path", required=True, help="Output path for certificate bundle")
parser.add_argument("--separate_files", dest="separate_files", required=False, 
                    action="store_true", help=("This will use --output_path as"
                        "a directory for writing individual certificate files."))
parser.add_argument("--identity_name", dest="dnsname", required=True, help="Identity DNS name")
# Filters by type
parser.add_argument("--dane_ee", dest="filter_dane_ee", required=False, action="store_true", help="Include DANE-EE.")
parser.add_argument("--pkix_ee", dest="filter_pkix_ee", required=False, action="store_true", help="Include PKIX-EE.")
parser.add_argument("--pkix_cd", dest="filter_pkix_cd", required=False, action="store_true", help="Include PKIX-CD.")
parser.set_defaults(separate_files=False, filter_dane_ee=False, filter_pkix_ee=False, filter_pkix_cd=False)

def main():
    """Wrap functionality provided by Identity.get_all_certificates()"""
    # Parse args
    args = parser.parse_args()
    filters = []
    if args.filter_dane_ee:
        filters.append("DANE-EE")
    if args.filter_pkix_ee:
        filters.append("PKIX-EE")
    if args.filter_pkix_cd:
        filters.append("PKIX-CD")
    # Get PKIX-CD certs from DNS
    identity = Identity(args.dnsname)
    certs = identity.get_all_certificates(filters=filters)
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