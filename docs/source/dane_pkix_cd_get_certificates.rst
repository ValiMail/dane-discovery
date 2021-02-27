Retrieve certificates from DNS
------------------------------

.. toctree::

::

    dane_pkix_cd_get_certificates  -h        
    usage: Retrieve and store all PKIX-CD certificates for an identity. [-h] --output_path OUT_PATH [--separate_files] --identity_name DNSNAME

    optional arguments:
      -h, --help            show this help message and exit
      --output_path OUT_PATH
                            Output path for certificate bundle
      --separate_files      This will use --output_path asa directory for writing individual certificate files.
      --identity_name DNSNAME
                            Identity DNS name
