# Snake issuer service

The issuer side of ArmisSnake: the REST service the ARMIS server calls to
personalize the applet at install ([issuer-openapi.yml](issuer-openapi.yml)),
plus the leaderboard that game UIs submit card-signed scores to
([docs/API.md](../docs/API.md)). Derived from RIA's
[armis-test-client-issuer-service](https://github.com/open-eid/armis-test-client-issuer-service)
0.1.11 (MIT, see [LICENSE-RIA](LICENSE-RIA)); the REST API, JSON format and
secure messaging code are unchanged. What differs:

- `PersonalizationSession`: INTERNAL AUTHENTICATE, then PUT DATA `5F20` with
  the player name and PUT DATA `DF02` with a random 16-byte player id. When the
  card has accepted both, the player is registered.
- `Player`: name and card key from the card holder certificate (ESTEID2018
  profile). The name is the given name, title-cased and cut to 16 UTF-8 bytes.
  The certificate itself, with the personal code, is not kept; a SHA-256 of it
  finds the player when ARMIS reports removal.
- `GET /v1/challenge`, `POST /v1/scores` (`Challenges`, `Scores`): single-use
  nonces, and checks of scores the card signed with its ARMIS key over
  `"armis-snake score" || player id || nonce || score`.
- `GET /v1/leaderboard?limit=10`: `[{"name": ..., "score": ...}]`, best score
  per player. In memory; `/v1/personalization/removed` and reinstalls drop the
  player's entry.
- No bundled key store: the issuer key is configured at runtime.
- Spring Boot 3.5, Bouncy Castle 1.86.

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

`mvn test` plays the ARMIS server against the service over REST and relays every
STORE DATA to ArmisSnake and the ARMIS Manager applet in jCardSim; Maven
compiles the applet and the harness from `../src` and `../test` itself. It then
plays a game on the card and submits the signed score like a UI. It checks
personalization of the name and player id, acceptance of a signed score,
rejection of a replayed nonce, a signature over another nonce, a tampered score
and a nonce the service did not issue, and removal.
