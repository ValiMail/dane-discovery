==============
dane-discovery
==============


A library for using
`DANE TLSA records <https://tools.ietf.org/html/rfc6698>`_ for
certificate discovery.


.. image:: https://readthedocs.org/projects/dane-discovery/badge/?version=latest
    :target: https://dane-discovery.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status


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
    dns_name = "butterfly.air-quality-sensor._mdevice.acme-manufacturing.net"
    tlsa_record = DANE.get_first_leaf_certificate(dns_name)
    if not tlsa_record:
        raise ValueError("No leaf certificate found for {}.".format(dns_name))

    der_cert = DANE.certificate_association_to_der(tlsa_record["certificate_association"])
    print(DANE.der_to_pem(der_cert))


`More examples <https://dane-discovery.readthedocs.io/en/latest/getting_started.html>`_
