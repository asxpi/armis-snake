package cardsnake;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.RandomData;

/**
 * Snake game state and rules.
 *
 * The board is 16x16, so a position fits in one byte as y << 4 | x. Each cell
 * takes 4 bits: empty, food, or a snake segment holding the direction to the
 * next segment towards the head, which the tail follows. Game state lives in
 * RAM (143 bytes) and is lost on deselect; the high score lives in EEPROM and
 * survives power-off.
 */
public final class SnakeGame {
    public static final byte INS_TICK = (byte) 0x10;   // P1 = direction, 0 keeps the current one
    public static final byte INS_NEW = (byte) 0x20;

    private static final byte UP = 1, RIGHT = 2, DOWN = 3, LEFT = 4;

    // Board cells: a segment is SEGMENT + direction - 1, so 2..5
    private static final byte EMPTY = 0, FOOD = 1, SEGMENT = 2;
    // Frame cells
    private static final byte F_EMPTY = 0, F_BODY = 1, F_HEAD = 2, F_FOOD = 3;
    private static final short CELLS = 256;

    private static final byte INIT = 0, PLAYING = 1, DEAD = 2, WON = 3;

    // Indices into st[]
    private static final short S_STATE = 0, S_HEAD = 1, S_TAIL = 2, S_LEN = 3,
            S_DIR = 4, S_SCORE = 5, S_FOOD = 6;

    // state(1) score(2) hiscore(2) length(2) board(64, 2 bits per cell)
    public static final short FRAME_LEN = 71;

    private final byte[] board;  // two cells per byte, first cell in the high nibble
    private final short[] st;
    private final byte[] rnd;
    private final RandomData rng;
    private short hiScore;

    public SnakeGame() {
        board = JCSystem.makeTransientByteArray((short) (CELLS / 2), JCSystem.CLEAR_ON_DESELECT);
        st = JCSystem.makeTransientShortArray((short) 7, JCSystem.CLEAR_ON_DESELECT);
        rnd = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    }

    public short getHiScore() {
        return hiScore;
    }

    /** Handles a game command and writes the frame to buf at offset 0. */
    public short process(byte ins, byte p1, byte[] buf) {
        switch (ins) {
        case INS_NEW:
            newGame();
            break;
        case INS_TICK:
            if (st[S_STATE] == INIT) {
                newGame();
            } else if (st[S_STATE] == PLAYING) {
                step(p1);
            }
            break;
        default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
        return writeFrame(buf);
    }

    private short cell(short p) {
        byte b = board[(short) (p >> 1)];
        return (short) ((p & 1) == 0 ? (b >> 4) & 0x0F : b & 0x0F);
    }

    private void setCell(short p, short value) {
        short i = (short) (p >> 1);
        board[i] = (byte) ((p & 1) == 0
                ? (short) (board[i] & 0x0F) | (short) (value << 4)
                : (short) (board[i] & 0xF0) | value);
    }

    /** The neighbour of p in direction dir; -1 off the board. */
    private static short move(short p, short dir) {
        short x = (short) (p & 0x0F);
        short y = (short) ((short) (p >> 4) & 0x0F);
        switch (dir) {
        case UP:    y--; break;
        case DOWN:  y++; break;
        case LEFT:  x--; break;
        default:    x++; break;
        }
        if (x < 0 || x > 15 || y < 0 || y > 15) {
            return -1;
        }
        return (short) ((short) (y << 4) | x);
    }

    private void newGame() {
        Util.arrayFillNonAtomic(board, (short) 0, (short) board.length, EMPTY);
        // Length 3 on row 8, columns 6..8, heading right
        for (short p = 0x86; p <= 0x88; p++) {
            setCell(p, (short) (SEGMENT + RIGHT - 1));
        }
        st[S_TAIL] = 0x86;
        st[S_HEAD] = 0x88;
        st[S_LEN] = 3;
        st[S_DIR] = RIGHT;
        st[S_SCORE] = 0;
        st[S_STATE] = PLAYING;
        placeFood();
    }

    private void step(byte want) {
        short dir = st[S_DIR];
        // Opposite directions differ by 2; turning back into the neck is ignored.
        if (want >= UP && want <= LEFT && (short) ((short) (want - dir) & 3) != 2) {
            dir = want;
        }
        st[S_DIR] = dir;

        short head = st[S_HEAD];
        short next = move(head, dir);
        if (next < 0) {
            gameOver(DEAD);
            return;
        }
        short tail = st[S_TAIL];
        boolean eat = next == st[S_FOOD];

        // The head may move into the cell the tail is leaving.
        if (cell(next) >= SEGMENT && (eat || next != tail)) {
            gameOver(DEAD);
            return;
        }
        if (!eat) {
            short tailDir = (short) (cell(tail) - SEGMENT + 1);
            setCell(tail, EMPTY);
            st[S_TAIL] = move(tail, tailDir);
        }
        short segment = (short) (SEGMENT + dir - 1);
        setCell(head, segment);  // now points at the new head
        setCell(next, segment);  // overwritten when the head moves on
        st[S_HEAD] = next;

        if (eat) {
            st[S_LEN]++;
            st[S_SCORE] += 10;
            placeFood();
        }
    }

    /** Drops food on a random free cell, using the card's RNG. */
    private void placeFood() {
        rng.generateData(rnd, (short) 0, (short) 1);
        short p = (short) (rnd[0] & 0xFF);
        for (short n = 0; n < CELLS; n++) {
            if (cell(p) == EMPTY) {
                setCell(p, FOOD);
                st[S_FOOD] = p;
                return;
            }
            p = (short) ((short) (p + 1) & 0xFF);
        }
        st[S_FOOD] = -1;
        gameOver(WON);
    }

    private void gameOver(byte state) {
        st[S_STATE] = state;
        if (st[S_SCORE] > hiScore) {
            hiScore = st[S_SCORE];
        }
    }

    private short frameCell(short p) {
        short c = cell(p);
        if (p == st[S_HEAD]) {
            return F_HEAD;
        }
        return c == EMPTY ? F_EMPTY : c == FOOD ? F_FOOD : F_BODY;
    }

    private short writeFrame(byte[] buf) {
        buf[0] = (byte) st[S_STATE];
        Util.setShort(buf, (short) 1, st[S_SCORE]);
        Util.setShort(buf, (short) 3, hiScore);
        Util.setShort(buf, (short) 5, st[S_LEN]);
        // Four cells per byte, first cell in the high bits
        for (short i = 0; i < 64; i++) {
            short c = (short) (i << 2);
            buf[(short) (7 + i)] = (byte) ((short) (frameCell(c) << 6)
                    | (short) (frameCell((short) (c + 1)) << 4)
                    | (short) (frameCell((short) (c + 2)) << 2)
                    | frameCell((short) (c + 3)));
        }
        return FRAME_LEN;
    }
}
