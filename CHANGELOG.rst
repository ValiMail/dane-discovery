Changelog
=========


v0.8
----

New
~~~
- Add dane_pkix_cd_get_ca_certificates. [Ash Wilson]

  Close #32
- Add dane_pkix_cd_get_certificates. [Ash Wilson]

  Close #31
- Add authenticate_pkix_cd script. [Ash Wilson]

  Close #29
- Add PKIX-CD validation for local certificates. [Ash Wilson]

  Close #28


v0.7 (2021-02-18)
-----------------

New
~~~
- Add certificate_object to output from Identity.process_tlsa() [Ash
  Wilson]

  Close #23
- Add support for EC certificates and keys. [Ash Wilson]

  Close #24


v0.6 (2020-11-10)
-----------------

New
~~~
- Add support for PKIX-CD. [Ash Wilson]

  Breaking changes! Test thoroughly before updating to this version!

  Close #20
- Add Identity.get_ca_certificate_for_identity() [Ash Wilson]

  Close #18
- Add Identity.verify_certificate_signature(). [Ash Wilson]


v0.5 (2020-10-15)
-----------------

Fix
~~~
- Clean up parsing of TLSA records when DNSSEC is in use. [Ash Wilson]


v0.4 (2020-10-15)
-----------------

Fix
~~~
- Fix parsing of full DNS response message. [Ash Wilson]


v0.3 (2020-10-15)
-----------------

New
~~~
- Identity __repr__() indicates request context and x509 extensions.
  [Ash Wilson]

Changes
~~~~~~~
- DANE.get_tlsa_records() returns request context. [Ash Wilson]


v0.2 (2020-08-13)
-----------------

New
~~~
- Support generating TLSA records for matching type 1, 2. [Ash Wilson]

  Closes #3


v0.1 (2020-08-04)
-----------------

New
~~~
- Add certificate_association_to_der() and der_to_pem() for formatting
  certs from TLSA RRs. [Ash Wilson]


