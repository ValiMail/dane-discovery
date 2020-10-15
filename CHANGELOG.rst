Changelog
=========


v0.4
----

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


