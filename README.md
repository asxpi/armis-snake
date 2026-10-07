# armis-snake

Snake as an [ARMIS](https://github.com/open-eid/armis-applet-ecosystem) client
applet for Estonian ID cards. This is Snake, because Doom doesn't fit.

The game runs entirely on the card and the high score is kept on the card; a
host only sends key presses and draws the returned board, including the high
score.

## Build and verify

```sh
git clone --recursive https://github.com/asxpi/armis-snake.git && cd armis-snake
nix build            # builds and tests in a sandbox; result/armis-snake.cap, result/SHA256SUMS
```

Expected for this revision:

```
031d66b6fb7843ff296cf822b1ab3de90c0f482bb74569d99f4d7fff6ba8492a  armis-snake.cap
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
# 7a31ccb7a2f24b9ea80e151c1efef02937441d5c10a2028f35bfef4300484f11
```

## Play

`client/snake.py` is a terminal client: arrows/WASD, `p` pause, `r` restart, `q` quit.

```sh
nix develop
ant test-classes
python3 client/snake.py                 # jCardSim card, installed through ARMIS by the test harness
python3 client/snake.py --eid 0         # show your given name from the ID card in PC/SC reader 0
python3 client/snake.py --pcsc 0        # real card with ArmisSnake installed
```

To build your own UI, see [docs/API.md](docs/API.md).

## Applet

| | |
|---|---|
| Platform | Java Card 3.0.4 Classic, GlobalPlatform 2.2.1 |
| Package / applet AID | `F0534E414B4541` / `F0534E414B454101` (proprietary, open to reassignment) |
| Imports | ARMIS ecosystem library `41524D49532D6C6962` version 0.0, javacard.framework, javacard.security, javacardx.crypto (through the library API), org.globalplatform |
| Load file | 1379 bytes of components, 1901 with the optional Descriptor (CAP 14730 bytes) |
| Persistent | high score (2 B); issuer public key and objects allocated by the ARMIS library |
| Transient, deselect | 143 B game state: 128 B board at 4 bits per cell, counters, RNG byte |

Sources: `src/cardsnake/SnakeGame.java` (rules, frame encoding) and
`src/cardsnake/ArmisSnake.java` (ARMIS integration).

| Command | APDU | Response |
|---|---|---|
| New game | `80 20 00 00 47` | frame |
| Move | `80 10 <dir> 00 47` | frame |

`dir`: 0 keep, 1 up, 2 right, 3 down, 4 left. Frame (71 bytes): state
(1 playing, 2 dead, 3 won), score, high score, length (u16 each), then the
16×16 board at 2 bits per cell. Full description in [docs/API.md](docs/API.md).

The board cells hold the direction to the next snake segment, so the tail
follows them and no list of positions is kept in RAM.

### ARMIS install

`AbstractApplet` handles it: ARMIS installs the CAP with the Manager AID and the
SHA-384 of the issuer's P-384 public key, the applet registers with the Manager
applet, and STORE DATA with the issuer public key finalizes the install. The
issuer sends no personalization commands, and the applet refuses any further
STORE DATA.

## Issuer service

ARMIS requires an issuer endpoint for every applet. [`issuer/`](issuer) is a
minimal one, based on RIA's test issuer service: it allows every install and
returns the issuer certificate, without personalization commands and without
storing anything.

## Testing on a real card

Until RIA provides test cards, a blank Java Card 3.0.4+ / GlobalPlatform 2.2.1
card with the features the ARMIS Manager needs (P-384 ECDH and ECDSA, object
deletion), such as NXP JCOP 4 J3R180, can run the real ARMIS tooling, with keys
you control. Untested so far.

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
5. Play with `client/snake.py --pcsc 0`.

## Security and privacy

- No access to eID data: the applet lives in the ARMIS SSD and cannot reach the
  eID application. It stores only its high score.
- No keys of its own and no personal data: nothing is sent to the card at
  install, and the issuer service stores nothing.
- The frame holds no unique data, so the same over contact and contactless.
- Food placement uses `RandomData.ALG_SECURE_RANDOM`.

## Tests

`ant test` (also run by `nix build`) plays ARMIS in jCardSim (Manager
personalization, install, STORE DATA) and covers the install, game rules, the
high score surviving deselection, and rejection of a wrong issuer key at
install, STORE DATA after the install and unknown commands. The issuer service
has its own tests; see [issuer/README.md](issuer/README.md).

Simulator differences from a card, all in `test/`: STORE DATA calls
`processData()` directly rather than through a security domain; the Manager
certificate is a DER stand-in with its raw public key; jCardSim generates the
same key pair on every simulated card; and the ARMIS sources are compiled with
`externalAccess=false`, which jCardSim requires. The CAP is built from the
unmodified sources.

## License

MIT, see [LICENSE](LICENSE).
