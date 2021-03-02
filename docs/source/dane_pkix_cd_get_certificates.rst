Retrieve certificates from DNS
------------------------------

.. toctree::

::

    dane_discovery_get_certificates -h
    usage: dane_discovery_get_certificates [-h] --output_path OUT_PATH [--separate_files] --identity_name DNSNAME [--dane_ee] [--pkix_ee] [--pkix_cd]

    Retrieve, authenticate, and store all certificates for a DANE identity. Default behavior retrieves and authenticates all available entity certificates. Adding
    filters for specific types (--pkix-cd, for instance) limits output to those types.

    optional arguments:
      -h, --help            show this help message and exit
      --output_path OUT_PATH
                            Output path for certificate bundle
      --separate_files      This will use --output_path asa directory for writing individual certificate files.
      --identity_name DNSNAME
                            Identity DNS name
      --dane_ee             Include DANE-EE.
      --pkix_ee             Include PKIX-EE.
      --pkix_cd             Include PKIX-CD.

