# Snake issuer service

The issuer side of ArmisSnake: the REST service the ARMIS server calls to
personalize the applet ([issuer-openapi.yml](issuer-openapi.yml)), plus a
leaderboard. Derived from RIA's
[armis-test-client-issuer-service](https://github.com/open-eid/armis-test-client-issuer-service)
0.1.11 (MIT, see [LICENSE-RIA](LICENSE-RIA)); the REST API, JSON format and
secure messaging code are unchanged. What differs:

- `PersonalizationSession`: INTERNAL AUTHENTICATE, then PUT DATA `5F20` with
  the player name, then GET DATA `DF01`; the high score goes to the leaderboard.
- `Player`: name and id from the card holder certificate (ESTEID2018 profile).
  The name is the given name, title-cased and cut to 16 UTF-8 bytes. The id is
  SHA-256 of the subject serial number, so the personal code is not stored.
- `Leaderboard`, `GET /v1/leaderboard?limit=10`: `[{"name": ..., "score": ...}]`.
  In memory; `/v1/personalization/removed` drops the player.
- No bundled key store: the issuer key is configured at runtime.
- Spring Boot 3.5, Bouncy Castle 1.86.

## Issuer key

[`issuer.crt`](issuer.crt) is the production issuer certificate: EC P-384,
self-signed, `C=EE, CN=Snake issuer`, valid 2026-10-07 to 2036-10-04. ARMIS
binds the applet to the SHA-384 of its public point:

```
dfef612c717084384e151981f80e3fbb474a023f72f904c2019573b5c27e8aaed4de6282dd9cfa33225b881d2861d8d2
```

```sh
openssl x509 -in issuer.crt -noout -pubkey | openssl pkey -pubin -outform DER | tail -c 97 | sha384sum
```

The private key is kept outside the repository.

## Run

```sh
nix develop .#issuer        # JDK 17, Maven
# Local testing: a throwaway key; production uses the key behind issuer.crt
keytool -genkeypair -keystore issuer.p12 -storetype PKCS12 -alias issuer-service \
  -keyalg EC -groupname secp384r1 -sigalg SHA384withECDSA -dname "CN=Snake issuer test" -validity 30
mvn package
ISSUER_SERVICE_SECURE_MESSAGING_KEY_STORE=file:issuer.p12 \
ISSUER_SERVICE_SECURE_MESSAGING_KEY_STORE_PASSWORD=... \
ISSUER_SERVICE_SECURE_MESSAGING_KEY_PASSWORD=... \
  java -jar target/snake-issuer-service-0.1.0-exec.jar
```

## Test

`mvn test` plays the ARMIS server against the service over REST and relays
every STORE DATA to ArmisSnake and the ARMIS Manager applet in jCardSim
(harness in `../test`). It checks personalization of the name from the
certificate, that a score played on the card reaches the leaderboard on the
next personalization, and removal.
