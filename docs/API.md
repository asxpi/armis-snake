# ArmisSnake card API

Everything a UI needs to play Snake on a card running ArmisSnake. The card holds
the whole game; a UI sends one APDU per move and draws the 71-byte frame it gets
back, and can submit the card-signed high score to the leaderboard.
[`client/snake.py`](../client/snake.py) is a complete reference client.

## Transport

ISO 7816-4 APDUs over PC/SC, contact interface (T=0 or T=1). Browsers cannot
send APDUs, so a UI is a native app or talks to a local helper that does
(pyscard, `javax.smartcardio`, `pcsc-lite`, WinSCard). Contactless works for the
game but has not been tested on ID cards; the player name and Sign score are
refused there.

The card has no timer: the UI decides the speed by how often it sends a move.

## Commands

| Command | APDU (hex) | Response data |
|---|---|---|
| Select | `00 A4 04 00 08 F0 53 4E 41 4B 45 41 01` | none |
| New game | `80 20 00 00 47` | frame |
| Move | `80 10 <dir> 00 47` | frame |
| Player name | `80 30 00 00 00` | 0–16 bytes, UTF-8 |
| Sign score | `80 40 00 00 20 <32-byte nonce> 00` | player id (16), high score (2), signature |

`dir` (P1): `00` keep going, `01` up, `02` right, `03` down, `04` left. Any
other value means keep going.

Select once per session. Game state lives in RAM and is lost when the applet
is deselected or the card is reset; the high score survives. A Move before
any New game starts a new game.

The player name and player id are set by the issuer through ARMIS when the
applet is installed. Sign score is described under [Submitting a score](#submitting-a-score).

### Status words

| SW | Meaning |
|---|---|
| `9000` | OK |
| `6A82` | ArmisSnake is not installed (on Select) |
| `6E00` | CLA is not `80` |
| `6D00` | Unknown INS |
| `6700` | Sign score nonce is not 32 bytes |
| `6985` | Player name or Sign score over contactless, or Sign score before personalization |

On T=0, readers may answer `6C47` or `61xx` first; PC/SC stacks usually resend
for you. Asking for exactly `47` (71) bytes avoids it.

## Frame

71 bytes:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | state: `1` playing, `2` dead, `3` won (board full) |
| 1 | 2 | score, big-endian |
| 3 | 2 | high score, big-endian |
| 5 | 2 | snake length, big-endian |
| 7 | 64 | board: 256 cells × 2 bits |

Cell values: `0` empty, `1` body, `2` head, `3` food. Cells are row-major from
the top-left, four per byte, first cell in the high bits:

```python
cells = [(b >> shift) & 3 for b in frame[7:71] for shift in (6, 4, 2, 0)]
x, y = i % 16, i // 16          # position of cells[i]
```

```js
const cells = [];
for (const b of frame.subarray(7, 71)) for (const s of [6, 4, 2, 0]) cells.push((b >> s) & 3);
```

## Rules

- The board is 16×16 with walls at the edges. A new game starts with length 3
  on row 8 (columns 6–8), head at (8, 8), moving right, and one food.
- Each Move advances the snake one cell. Turning straight back into the neck
  is ignored, so a UI may forward every key press.
- Hitting a wall or the body ends the game (state 2). Moving into the cell the
  tail is leaving is allowed.
- Eating food adds 10 to the score and 1 to the length; new food appears on a
  random free cell (card RNG). A full board ends the game as won (state 3).
- The high score updates when a game ends, so during play it shows the best
  finished game. After the game ends, Move returns the final frame unchanged
  until New game.

## Example

Python with pyscard; error handling left out:

```python
from smartcard.System import readers

card = readers()[0].createConnection()
card.connect()
card.transmit(list(bytes.fromhex("00A4040008F0534E414B454101")))
name, sw1, sw2 = card.transmit([0x80, 0x30, 0, 0, 0])
frame, sw1, sw2 = card.transmit([0x80, 0x20, 0, 0, 0x47])
while frame[0] == 1:
    frame, sw1, sw2 = card.transmit([0x80, 0x10, read_direction(), 0, 0x47])
    draw(frame)
```

## Submitting a score

The UI relays; the card and the leaderboard do the checking. No PIN is needed:
the card signs with its ARMIS key, not with the eID keys.

1. `GET /v1/challenge` returns `{"nonce": "<Base64, 32 bytes>"}`, valid once
   for 2 minutes.
2. Send Sign score with that nonce. The card returns player id (16 bytes),
   high score (2 bytes, big-endian) and an ECDSA-SHA384 signature (DER) by its
   ARMIS card key over:

   ```
   "armis-snake score" (17 ASCII bytes) || player id || nonce || high score
   ```

3. `POST /v1/scores` with `{"nonce": "<Base64>", "signedScore": "<Base64 of the
   whole Sign score response>"}`. The leaderboard checks the nonce, finds the
   player by id and verifies the signature with the card key it got at install.

| Status | Body | Meaning |
|---|---|---|
| `200` | `{"name": "Mari-Liis", "score": 210}` | accepted; the player's best score |
| `400` | none | a field is missing |
| `403` | none | unknown or used nonce, unknown player, or bad signature |

The signed score is the card's high score, so submit after a game ends; a
lower score never replaces a higher one.

## Leaderboard

```
GET /v1/leaderboard?limit=10        (limit 1–100, default 10)
[{"name": "Mari-Liis", "score": 210}, ...]
```

The ARMIS-facing endpoints of the same service are in
[`issuer/issuer-openapi.yml`](../issuer/issuer-openapi.yml) and are not for UIs.

## Without a card

`ant test-classes` builds a jCardSim card that `cardsnake.sim.Bridge` exposes
on stdin/stdout: one APDU per line in hex, one response (data + SW) per line
in hex. Start it with the player name as the only argument:

```sh
JCARDSIM_OBJECT_DELETION_SUPPORTED=1 java \
  -cp build/test:lib/jcardsim.jar:ext/armis-applet-ecosystem/ext/gp-exports/org.globalplatform-1.6/gpapi-globalplatform.jar \
  cardsnake.sim.Bridge Mari
```

The line `#hiscore` makes the card sign its high score and answers with the
score after checking the signature with the card key, as the leaderboard would.
The simulated card's player id is all zeros.
