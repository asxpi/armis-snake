# armis-snake

Snake as an [ARMIS](https://github.com/open-eid/armis-applet-ecosystem) client
applet for Estonian ID cards. This is Snake, because Doom doesn't fit.

The game runs entirely on the card; a host only sends key presses and draws the
returned board. When a game is over, the card signs its high score with its
ARMIS card key, so any UI can relay the score to the leaderboard and the
leaderboard can check that it was played on that card.

## Build and verify

```sh
git clone --recursive https://github.com/asxpi/armis-snake.git && cd armis-snake
nix build            # builds and tests in a sandbox; result/armis-snake.cap, result/SHA256SUMS
```

Expected for this revision:

```
f675ae819c3bb2c9c52f1cd7fc67d8b025d2ea914a291e0ab7229cf38a11de28  armis-snake.cap
```

The build is pinned end to end: nixpkgs (JDK 11, Ant) by `flake.lock`, the ARMIS
SDK by the `ext/armis-applet-ecosystem` submodule (which pins the Java Card
3.0.4 kit and GlobalPlatform exports), ant-javacard and jCardSim by SHA-256.
`tools/NormalizeCap.java` fixes zip timestamps and the manifest creation time;
the CAP components are left as the converter produced them.

Without Nix (JDK 11, Ant 1.10): `ant cap test`. A different JDK 11 build may
change the manifest's `Created-By` line; the components that are loaded onto
the card should still match:

```sh
unzip -p build/armis-snake.cap 'cardsnake/javacard/*.cap' | sha256sum
# 293b401bb7144daa895c84b32586dd09f8aa753de15dba972ed7e8d23acee81e
```

## Play

`client/snake.py` is a terminal client: arrows/WASD, `p` pause, `r` restart, `q` quit.

```sh
nix develop
ant test-classes
python3 client/snake.py --name Mari     # jCardSim card, ARMIS lifecycle run by the test harness
python3 client/snake.py --eid 0         # same, name read from the ID card in PC/SC reader 0
python3 client/snake.py --pcsc 0 --leaderboard https://…/v1   # real card, submit the score on quit
```

In jCardSim, quitting shows the card-signed high score after checking the
signature with the card key, as the leaderboard would.

To build your own UI, see [docs/API.md](docs/API.md): commands, frame format,
game rules, score submission and the leaderboard.

## Applet

| | |
|---|---|
| Platform | Java Card 3.0.4 Classic, GlobalPlatform 2.2.1 (`Personalization`) |
| Package / applet AID | `F0534E414B4541` / `F0534E414B454101` (proprietary, open to reassignment) |
| Imports | ARMIS ecosystem library `41524D49532D6C6962` version 0.0, javacard.framework, javacard.security, javacardx.crypto, org.globalplatform |
| Load file | 3416 bytes of components, 2571 without the optional Descriptor (CAP 21774 bytes) |
| Persistent | high score (2 B), player name (≤ 16 B), player id (16 B), issuer public key (ARMIS library) |
| Transient, deselect | 143 B game state: 128 B board at 4 bits per cell, counters, RNG byte |
| Transient, reset | AES-256 session key (32 B), 1 flag |

Sources: `src/cardsnake/SnakeGame.java` (rules, frame encoding) and
`src/cardsnake/ArmisSnake.java` (ARMIS integration, score signing).

RAM is the scarce resource, and `CLEAR_ON_RESET` RAM stays reserved for the
applet even when it is not in use. The board cells hold the direction to the
next snake segment, so the tail follows them and no list of positions is kept.
The ConcatKDF block is computed in the temporary global array the ECDHE secret
arrives in, instead of a reserved buffer.

### Cardholder interface (plain APDUs)

| Command | APDU | Response |
|---|---|---|
| New game | `80 20 00 00 47` | frame |
| Move | `80 10 <dir> 00 47` | frame |
| Player name | `80 30 00 00 00` (contact only) | UTF-8 name |
| Sign score | `80 40 00 00 20 <nonce> 00` (contact only) | player id, high score, signature |

`dir`: 0 keep, 1 up, 2 right, 3 down, 4 left. Frame (71 bytes): state
(1 playing, 2 dead, 3 won), score, high score, length (u16 each), then the
16×16 board at 2 bits per cell. Full description in [docs/API.md](docs/API.md).

Sign score asks the Manager applet, through the ARMIS `forSigning` SIO, to sign
`"armis-snake score" || player id || nonce || high score` with ECDSA-SHA384 and
the card key. The fixed prefix keeps the card key from signing host-chosen data
that could mean something else, such as an ECDHE ephemeral key.

### Issuer interface (STORE DATA via ARMIS, once at install)

1. Install parameters: Manager AID and SHA-384 of the issuer's P-384 public
   key; the applet registers with the Manager applet.
2. STORE DATA with the issuer public key finalizes the install.
3. INTERNAL AUTHENTICATE (`88`): the issuer's ephemeral key, signed by the
   issuer. The applet verifies it, runs ECDHE through the Manager's card key and
   returns its ephemeral key signed by the Manager. Both sides derive AES-256
   with ConcatKDF(SHA-384), as in `armis-test-client-issuer-service`.
4. Over secure messaging: PUT DATA `5F20` sets the player name, PUT DATA `DF02`
   sets the 16-byte player id the card signs with every score.

ARMIS personalizes an applet only at install, so scores reach the leaderboard
through Sign score instead.

## Issuer service

[`issuer/`](issuer) is the leaderboard service. ARMIS calls it at install to
personalize the applet; it takes the player name and the card key from the
card holder certificate and assigns a player id. UIs then submit scores signed
by the card. It is a fork of RIA's test issuer service with the same ARMIS
REST API.

## Testing on a real card

Until RIA provides test cards, a blank Java Card 3.0.4+ / GlobalPlatform 2.2.1
card with P-384 ECDH and ECDSA, AES-256 and object deletion (e.g. NXP JCOP 4
J3R180) can run the real ARMIS tooling, with keys you control. Untested so far.

1. Get [`armis-cli.jar`](https://github.com/open-eid/armis-cli/releases) v0.11.0,
   and the ARMIS library and Manager CAPs from `prebuilt/applets/` in the
   armis-cli repository.
2. Set up a security domain armis-cli can open (`--armis.sd-aid`, `--armis.sd-key`,
   `--armis.sd-key-diversification`), e.g. with
   [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro), and an
   RSA DM key (`--armis.dm-key`).
3. `--armis.action=deploy-manager` with the library and Manager CAPs.
4. Start the issuer service (see [issuer/README.md](issuer/README.md)), then
   `--armis.action=deploy-client --armis.client-cap-file=file:result/armis-snake.cap
   --armis.client-aid=F0534E414B454101 --armis.client-instance-aid=F0534E414B454101
   --armis.issuer-url=http://localhost:8080/v1`. Use `sign` first if the card
   requires DAP.
5. Play with `client/snake.py --pcsc 0 --leaderboard http://localhost:8080/v1`
   and check `GET /v1/leaderboard`.

## Security and privacy

- No access to eID data: the applet lives in the ARMIS SSD and cannot reach the
  eID application, and score signing uses the ARMIS card key, not the eID keys,
  so no PIN is involved.
- No private keys of its own: ECDHE and signing go through the Manager's SIO.
- Nothing identifying over contactless: the frame holds no unique data, and the
  player name and Sign score are refused unless the contact interface is used.
- Selecting the applet ends any issuer session; issuer commands are reachable
  only through STORE DATA, never as plain APDUs.
- A score cannot be changed or replayed by the host: it is computed on the card,
  signed together with a single-use leaderboard nonce, and checked against the
  card key from the certificate. A bot can still play on a real card.
- Food placement uses `RandomData.ALG_SECURE_RANDOM`.
- The issuer service keeps the player name, the card public key, a hash of the
  certificate and the best score, not the certificate or personal code, and
  drops them when ARMIS reports the applet removed.
- Inherited from the ARMIS library: SM MACs are not computed yet (zero bytes,
  marked TODO upstream), so SM gives confidentiality but not integrity.

## Tests

`ant test` (also run by `nix build`) plays both off-card roles in jCardSim:
ARMIS (Manager personalization, install, STORE DATA) and the issuer (signed
ECDHE, SM). It covers the lifecycle, game rules, signed scores and their
rejection when the score, player id, nonce or card key differ, and rejection of
a wrong issuer key at install, a wrongly signed INTERNAL AUTHENTICATE, SM
without a session, SM after reselection, signing before personalization or with
a bad nonce, oversized names and unknown commands. The issuer service has its
own tests; see [issuer/README.md](issuer/README.md).

Simulator differences from a card, all in `test/`: STORE DATA calls
`processData()` directly rather than through a security domain; the Manager
certificate is a DER stand-in with its raw public key; jCardSim generates the
same key pair on every simulated card; and the ARMIS sources are compiled with
`externalAccess=false`, which jCardSim requires. The CAP is built from the
unmodified sources.

## License

MIT, see [LICENSE](LICENSE).
