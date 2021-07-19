==============
dane-discovery
==============


A library for using
`DANE TLSA records <https://tools.ietf.org/html/rfc6698>`_ for
certificate discovery.


.. image:: https://readthedocs.org/projects/dane-discovery/badge/?version=latest
    :target: https://dane-discovery.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status


.. image:: https://circleci.com/gh/ValiMail/dane-discovery.svg?style=shield
    :target: https://circleci.com/gh/ValiMail/dane-discovery


.. image:: https://api.codeclimate.com/v1/badges/ec76c78dc4ac97b4b5f7/maintainability
    :target: https://codeclimate.com/github/ValiMail/dane-discovery/maintainability
    :alt: Maintainability


.. image:: https://api.codeclimate.com/v1/badges/ec76c78dc4ac97b4b5f7/test_coverage
   :target: https://codeclimate.com/github/ValiMail/dane-discovery/test_coverage
   :alt: Test Coverage


Quick Start
===========

Installation
------------

``pip install dane-discovery``


Load a certificate from DNS and print the PEM representation
------------------------------------------------------------

.. code-block:: python

    from dane_discovery.dane import DANE
    from dane_discovery.pki import PKI
    dns_name = "dns.name.having.a.tlsa.record"
    tlsa_record = DANE.get_first_leaf_certificate(dns_name)
    if not tlsa_record:
        raise ValueError("No leaf certificate found for {}.".format(dns_name))

    der_cert = PKI.certificate_association_to_der(tlsa_record["certificate_association"])
    print(PKI.der_to_pem(der_cert))



Load a DANE identity from DNS and print the request context
-----------------------------------------------------------


.. code-block:: python

    from dane_discovery.identity import Identity
    dns_name = "dns.name.having.a.tlsa.record"
    dane_identity = Identity(dns_name)
    print(dane_identity.report())

    Name: abc123.air-quality-sensor._device.example.net
    Request context:
      DNSSEC: False
      TLS: False
      TCP: True
    Credential index: 0
      certificate usage: DANE-EE
      selector: Full certificate match
      matching type: Exact match against certificate association
      x509 attributes:
        {'extensions': {'BasicConstrints': {'ca': False, 'path_length': None},
                        'KeyUsage': {'content_commitment': True,
                                     'crl_sign': False,
                                     'data_encipherment': False,
                                     'digital_signature': True,
                                     'key_agreement': False,
                                     'key_cert_sign': False,
                                     'key_encipherment': True}},
         'subject': {'commonName': 'abc123.air-quality-sensor._device.example.net',
                     'countryName': 'US',
                     'organizationName': 'Example Networks',
                     'stateOrProvinceName': 'CA'}}





`More examples <https://dane-discovery.readthedocs.io/en/latest/getting_started.html>`_
