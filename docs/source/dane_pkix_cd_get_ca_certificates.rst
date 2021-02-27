Download all CA certificates for an identity
--------------------------------------------

.. toctree::

::

    dane_pkix_cd_get_ca_certificates -h
    usage: Retrieve and store all CA certificates required for PKIX-CD authentication of an identity. [-h] --output_path OUT_PATH [--separate_files] --identity_name DNSNAME

    optional arguments:
      -h, --help            show this help message and exit
      --output_path OUT_PATH
                            Output path for certificate bundle
      --separate_files      This will use --output_path asa directory for writing individual certificate files.
      --identity_name DNSNAME
                            Identity DNS name
