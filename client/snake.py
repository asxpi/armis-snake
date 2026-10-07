#!/usr/bin/env python3
"""Terminal client for ArmisSnake: the card runs the game, this only sends keys and draws.

Plays against ArmisSnake in jCardSim (run `ant test-classes` first) or on a real
card over PC/SC. The high score is kept on the card.
"""
import argparse
import os
import select
import subprocess
import sys
import termios
import time
import tty
from collections import deque
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GP_API = ROOT / "ext/armis-applet-ecosystem/ext/gp-exports/org.globalplatform-1.6/gpapi-globalplatform.jar"
AID = bytes.fromhex("F0534E414B454101")
INS_TICK, INS_NEW = 0x10, 0x20
FRAME_LEN = 71

# Estonian ID card: (eID application AID, SELECT for the personal data DF), per chip generation
EID_LAYOUTS = [
    ("A000000063504B43532D3135", "00A4040C0D" + b"Document Data".hex()),  # Thales 2025
    ("A000000077010800070000FE00000100", "00A4010C025000"),  # IDEMIA
]
EID_GIVEN_NAME = "00A4020C025002"

UP, RIGHT, DOWN, LEFT = 1, 2, 3, 4
KEYS = {"\x1b[A": UP, "\x1b[C": RIGHT, "\x1b[B": DOWN, "\x1b[D": LEFT,
        "w": UP, "d": RIGHT, "s": DOWN, "a": LEFT}
CELL = ["\x1b[48;5;234m  ", "\x1b[48;5;28m  ", "\x1b[48;5;46m  ", "\x1b[48;5;234m\x1b[38;5;196m()"]
STATUS = {2: "GAME OVER  r: restart", 3: "YOU WIN  r: restart"}


class Sim:
    """ArmisSnake installed through ARMIS in jCardSim, via cardsnake.sim.Bridge."""

    def __init__(self):
        cp = os.pathsep.join(str(p) for p in (ROOT / "build/test", ROOT / "lib/jcardsim.jar", GP_API))
        if not (ROOT / "build/test/cardsnake/sim/Bridge.class").exists():
            sys.exit("run `ant test-classes` first")
        self.p = subprocess.Popen(["java", "-cp", cp, "cardsnake.sim.Bridge"],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                                  env={**os.environ, "JCARDSIM_OBJECT_DELETION_SUPPORTED": "1"})

    def transmit(self, apdu):
        self.p.stdin.write(apdu.hex() + "\n")
        self.p.stdin.flush()
        return bytes.fromhex(self.p.stdout.readline().strip())


class Pcsc:
    """A real card in a PC/SC reader."""

    def __init__(self, index):
        from smartcard.System import readers
        self.conn = readers()[index].createConnection()
        self.conn.connect()

    def transmit(self, apdu):
        data, sw1, sw2 = self.conn.transmit(list(apdu))
        return bytes(data + [sw1, sw2])


def send(card, apdu):
    r = card.transmit(apdu)
    if r[-2:] != b"\x90\x00":
        sys.exit(f"card returned SW {r[-2:].hex().upper()} for {apdu.hex().upper()}")
    return r[:-2]


def read_eid_name(index):
    """Given name from an Estonian ID card. The personal data file needs no PIN over contact."""
    card = Pcsc(index)
    for app, data_df in EID_LAYOUTS:
        if card.transmit(bytes.fromhex(f"00A4040C{len(app) // 2:02X}{app}"))[-2:] == b"\x90\x00":
            send(card, bytes.fromhex(data_df))
            send(card, bytes.fromhex(EID_GIVEN_NAME))
            return send(card, bytes.fromhex("00B0000000")).rstrip(b"\x00").decode().title()
    sys.exit("no Estonian eID application on the card")


def draw(frame, ms, player):
    state = frame[0]
    score, hi, length = (int.from_bytes(frame[i:i + 2], "big") for i in (1, 3, 5))
    cells = [(b >> s) & 3 for b in frame[7:FRAME_LEN] for s in (6, 4, 2, 0)]
    out = ["\x1b[H\x1b[0m+" + "-" * 32 + "+"]
    for y in range(16):
        out.append("|" + "".join(CELL[c] for c in cells[y * 16:y * 16 + 16]) + "\x1b[0m|")
    out.append("+" + "-" * 32 + "+")
    out.append(f" {player + '  ' if player else ''}score {score:<4} hi {hi:<4} len {length:<3} card {ms:5.1f} ms\x1b[K")
    out.append(f" {STATUS.get(state, 'arrows/wasd  p: pause  q: quit')}\x1b[K")
    sys.stdout.write("\r\n".join(out))
    sys.stdout.flush()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pcsc", type=int, metavar="N", help="play on the card in PC/SC reader N instead of jCardSim")
    ap.add_argument("--name", default="", help="player name to show")
    ap.add_argument("--eid", type=int, metavar="N",
                    help="show the given name from the ID card in PC/SC reader N (no PIN needed)")
    ap.add_argument("--tick", type=float, default=0.15, help="seconds per move (default 0.15)")
    args = ap.parse_args()

    player = read_eid_name(args.eid) if args.eid is not None else args.name
    card = Sim() if args.pcsc is None else Pcsc(args.pcsc)
    r = card.transmit(bytes([0x00, 0xA4, 0x04, 0x00, len(AID)]) + AID)
    if r[-2:] != b"\x90\x00":
        sys.exit(f"ArmisSnake not found on the card (SW {r[-2:].hex().upper()})")

    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd)
    tty.setcbreak(fd)
    sys.stdout.write("\x1b[?25l\x1b[2J")
    try:
        draw(send(card, bytes([0x80, INS_NEW, 0, 0, FRAME_LEN])), 0, player)
        turns, paused, ms = deque(maxlen=3), False, 0.0
        due = time.monotonic() + args.tick
        while True:
            if select.select([fd], [], [], max(0, due - time.monotonic()))[0]:
                key = os.read(fd, 8).decode(errors="ignore")
                if key == "q":
                    break
                if key == "p":
                    paused = not paused
                elif key == "r":
                    turns.clear()
                    draw(send(card, bytes([0x80, INS_NEW, 0, 0, FRAME_LEN])), ms, player)
                elif (d := KEYS.get(key if key.startswith("\x1b") else key.lower())):
                    turns.append(d)
                continue
            due += args.tick
            if paused:
                continue
            t0 = time.perf_counter()
            frame = send(card, bytes([0x80, INS_TICK, turns.popleft() if turns else 0, 0, FRAME_LEN]))
            ms = (time.perf_counter() - t0) * 1000
            draw(frame, ms, player)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)
        sys.stdout.write("\x1b[0m\x1b[?25h\r\n")


if __name__ == "__main__":
    main()
