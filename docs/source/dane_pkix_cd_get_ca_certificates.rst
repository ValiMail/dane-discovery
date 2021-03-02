Download all CA certificates for an identity
--------------------------------------------

.. toctree::

::

    dane_discovery_get_ca_certificates -h
    usage: dane_discovery_get_ca_certificates [-h] --output_path OUT_PATH [--separate_files] --identity_name DNSNAME

    Retrieve and store all CA certificates required for PKIX-CD authentication of an identity.

    optional arguments:
      -h, --help            show this help message and exit
      --output_path OUT_PATH
                            Output path for certificate bundle
      --separate_files      This will use --output_path asa directory for writing individual certificate files. Individual CA certificate files will be named
                            AUTHORITY_HOSTNAME-CA-subjectKeyID.crt.pem
      --identity_name DNSNAME
                            Identity DNS name
