Getting Started
===============

.. toctree::

Create a TLSA record
--------------------

Generate a TLSA record for a certificate.

.. code-block:: python

  from dane_discovery.dane import DANE
  with open("path/to/your/cert.pem", "rb") as file:
          certificate = file.read()
  print(DANE.generate_tlsa_record(3, 0, 0, certificate))


TLSA to PEM
-----------

Load a certificate from DNS and print the PEM representation

.. code-block:: python

    from dane_discovery.dane import DANE
    from dane_discovery.pki import PKI
    dns_name = "dns.name.where.a.cert.tlsa.can.be.found"
    tlsa_record = DANE.get_first_leaf_certificate(dns_name)
    if not tlsa_record:
        raise ValueError("No leaf certificate found for {}.".format(dns_name))

    der_cert = PKI.certificate_association_to_der(tlsa_record["certificate_association"])
    print(PKI.der_to_pem(der_cert))


TLSA to x.509
-------------

Generate an x.509 object from a certificate in a TLSA record

.. code-block:: python

    from dane_discovery.dane import DANE
    from dane_discovery.pki import PKI
    dns_name = "dns.name.of.tlsa_record"
    tlsa_records = DANE.get_tlsa_records(dns_name)
    tlsa_record = tlsa_records[0]
    if tlsa_record["matching_type"] != 0:
        print("This is not configured as a certificate-bearing TLSA record.")
    certificate_association = tlsa_record["certificate_association"]
    x509_obj = PKI.build_x509_object(certificate_association)
    print(x509_obj.subject)


Further Exploration
-------------------

From the Certificate object we retrieved in the prior example, we can extract
the public key, and read the various attributes of the certificate. For more
information, continue reading in the
`Python cryptography library <https://cryptography.io/en/latest/x509/reference/#x-509-certificate-object>`_
