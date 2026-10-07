# armis-snake

Snake as an [ARMIS](https://github.com/open-eid/armis-applet-ecosystem) client
applet for Estonian ID cards. The game runs entirely on the card; a host only
sends key presses and draws the returned board. The issuer is a leaderboard
service: since the score is computed on the card, a score read through ARMIS
was really played on that card.

## Build and verify

```sh
git clone --recursive <this repo> && cd armis-snake
nix build            # builds and tests in a sandbox; result/armis-snake.cap, result/SHA256SUMS
```

Expected for this revision:

```
1d734df0a6bd2122707b28c5cdc4e34b93f781d8bf423a3167823e4cb066c64d  armis-snake.cap
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
# 8aa0360ac9c293863cd5bdd871e73c2b5ea134f9a7e6ceef469c2ad2117860b0
```

## Applet

| | |
|---|---|
| Platform | Java Card 3.0.4 Classic, GlobalPlatform 2.2.1 (`Personalization`) |
| Package / applet AID | `F0534E414B4541` / `F0534E414B454101` (proprietary, open to reassignment) |
| Imports | ARMIS ecosystem library `41524D49532D6C6962` 0.0, javacard.framework, javacard.security, javacardx.crypto, org.globalplatform |
| Load file | 2926 bytes of components (CAP 19452 bytes) |
| Persistent | high score (2 B), player name (≤ 16 B), issuer public key (ARMIS library) |
| Transient, deselect | 527 B game state (board, snake, counters, RNG byte) |
| Transient, reset | 80 B KDF buffer, AES-256 session key, 1 flag |

Sources: `src/cardsnake/SnakeGame.java` (rules, frame encoding) and
`src/cardsnake/ArmisSnake.java` (ARMIS integration).

### Cardholder interface (plain APDUs)

| Command | APDU | Response |
|---|---|---|
| New game | `80 20 00 00 47` | frame |
| Move | `80 10 <dir> 00 47` | frame |
| Player name | `80 30 00 00 00` (contact only) | UTF-8 name |

`dir`: 0 keep, 1 up, 2 right, 3 down, 4 left. Frame (71 bytes): state
(0 init, 1 playing, 2 dead, 3 won), score, high score, length (u16 each), then
the 16×16 board at 2 bits per cell (0 empty, 1 body, 2 head, 3 food).

### Issuer interface (STORE DATA via ARMIS)

1. Install parameters: Manager AID and SHA-384 of the issuer's P-384 public
   key; the applet registers with the Manager applet.
2. STORE DATA with the issuer public key finalizes the install.
3. INTERNAL AUTHENTICATE (`88`): the issuer's ephemeral key, signed by the
   issuer. The applet verifies it, runs ECDHE through the Manager's card key and
   returns its ephemeral key signed by the Manager. Both sides derive AES-256
   with ConcatKDF(SHA-384), as in `armis-test-client-issuer-service`.
4. Over secure messaging: PUT DATA `5F20` sets the player name, GET DATA `DF01`
   returns the high score.

## Security and privacy

- No access to eID data: the applet lives in the ARMIS SSD and cannot reach the
  eID application. It stores only what the issuer sets and the high score.
- No private keys of its own: ECDHE and signing go through the Manager's SIO.
- Nothing identifying over contactless: the frame holds no unique data, and the
  player name is refused unless the contact interface is used.
- Selecting the applet ends any issuer session; issuer commands are reachable
  only through STORE DATA, never as plain APDUs.
- Food placement uses `RandomData.ALG_SECURE_RANDOM`.
- Inherited from the ARMIS library: SM MACs are not computed yet (zero bytes,
  marked TODO upstream), so SM gives confidentiality but not integrity.

## Tests

`ant test` (also run by `nix build`) plays both off-card roles in jCardSim:
ARMIS (Manager personalization, install, STORE DATA) and the issuer (signed
ECDHE, SM). It covers the lifecycle, game rules, the issuer reading a played
score, and rejection of a wrong issuer key at install, a wrongly signed
INTERNAL AUTHENTICATE, SM without a session, SM after reselection, oversized
names and unknown commands.

Simulator differences from a card, all in `test/`: STORE DATA calls
`processData()` directly rather than through a security domain; the Manager
certificate is a DER stand-in with its raw public key; and the ARMIS sources are
compiled with `externalAccess=false`, which jCardSim requires. The CAP is built
from the unmodified sources.

## License

MIT, see [LICENSE](LICENSE).
