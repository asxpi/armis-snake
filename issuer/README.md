# Snake issuer service

ARMIS requires an issuer endpoint for every applet
([issuer-openapi.yml](issuer-openapi.yml)). ArmisSnake needs no
personalization, so this one is minimal: `/personalization/start` allows every
install and returns the issuer certificate with no commands,
`/personalization/continue` aborts (ARMIS only calls it after a command), and
`/personalization/removed` is acknowledged. Nothing is stored.

Derived from RIA's
[armis-test-client-issuer-service](https://github.com/open-eid/armis-test-client-issuer-service)
0.1.11 (MIT, see [LICENSE-RIA](LICENSE-RIA)): same REST API and JSON format,
with the personalization session and secure messaging removed. Spring Boot 3.5.

## Issuer key

[`issuer.crt`](issuer.crt) holds the production issuer public key: EC P-384,
`C=EE, CN=Snake issuer`, valid 2026-10-07 to 2036-10-04. It is self-signed for
now; ARMIS accepts only issuer certificates from its required CA with a good
OCSP status, so this key still needs a CA-issued certificate. ARMIS binds the
applet to the SHA-384 of the public point, which stays the same:

```
dfef612c717084384e151981f80e3fbb474a023f72f904c2019573b5c27e8aaed4de6282dd9cfa33225b881d2861d8d2
```

```sh
openssl x509 -in issuer.crt -noout -pubkey | openssl pkey -pubin -outform DER | tail -c 97 | sha384sum
```

The service only needs the certificate. The private key stays offline; it is
needed only to request the CA-issued certificate.

## Run

```sh
nix develop .#issuer        # JDK 17, Maven
mvn package
java -jar target/snake-issuer-service-0.1.0-exec.jar      # serves issuer.crt from the working directory
```

Set `ISSUER_SERVICE_CERTIFICATE=file:/path/to/cert` to serve another certificate.

## Test

`mvn test` calls the three endpoints as the ARMIS server does and checks that
start returns `issuer.crt` without a command, continue aborts and removed is
acknowledged.
