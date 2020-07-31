Getting Started
===============

.. toctree::

Create a TLSA record
--------------------

.. code-block:: python

  from dane_discovery.dane import DANE
  with open("path/to/your/cert.pem", "rb") as file:
          certificate = file.read()
  print(DANE.generate_tlsa_record(3, 0, 0, certificate))


Generate an x.509 object from a certificate in a TLSA record
------------------------------------------------------------

.. code-block:: python

    from dane_discovery.dane import DANE
    dns_name = "dns.name.of.tlsa_record"
    tlsa_records = DANE.get_tlsa_records(dns_name)
    tlsa_record = tlsa_records[0]
    if tlsa_record["matching_type"] != 0:
        print("This is not configured as a certificate-bearing TLSA record.")
    certificate_association = tlsa_record["certificate_association"]
    x509_obj = DANE.build_x509_object(certificate_association)
    print(x509_obj.subject)


Further Exploration
-------------------

From the Certificate object we retrieved in the prior example, we can extract
the public key, and read the various attributes of the certificate. For more
information, continue reading `here <https://cryptography.io/en/latest/x509/reference/#x-509-certificate-object>`_`
