"""Authenticate a certificate using DANE PKIX-CD mode."""
import argparse
import sys

from dane_discovery.pki import PKI
from dane_discovery.identity import Identity


parser = argparse.ArgumentParser(description="Authenticate a local certificate using PKIX-CD")
parser.add_argument("--certificate_path", dest="cert_path", required=True, help="Path to certificate")
parser.add_argument("--identity_name", dest="dnsname", required=False, help="Identity DNS name")
parser.add_argument("--silent", dest="silent", action="store_true", help="No output, only exit code")
parser.set_defaults(silent=False, dnsname=None)


def main():
    """Wrap functionality provided by Identity.validate_certificate()"""
    # Parse args
    args = parser.parse_args()
    # Load cert from file
    try:
        cert_file = get_file_contents(args.cert_path)
    except Exception as err:
        exit_handler(False, str(err), args.silent)
    # Determine DNS name
    try:
        if not args.dnsname:
            cert_obj = PKI.build_x509_object(cert_file)
            dns_name = PKI.get_dnsnames_from_cert(cert_obj)[0]
        else:
            dns_name = args.dnsname 
    except IndexError:
        exit_handler(False, "No DNS name via args or certificate.", args.silent)
    # Run validator
    identity = Identity(dns_name)
    success, msg = identity.validate_certificate(cert_file)
    # Return results
    exit_handler(success, msg, args.silent)


def get_file_contents(file_path):
    """Get the contents of a file."""
    with open(file_path) as f_obj:
        return f_obj.read()


def exit_handler(success, msg, silent):
    """Handle exiting gracefully."""
    if not silent:
        print(msg)
    if success:
        sys.exit(0)
    exit(1)


if __name__ == "__main__":
    main()