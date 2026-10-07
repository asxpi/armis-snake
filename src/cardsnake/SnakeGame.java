package cardsnake;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.RandomData;

/**
 * Snake game state and rules.
 *
 * The board is 16x16, so a position fits in one byte as y << 4 | x.
 * Game state lives in RAM and is lost on deselect; the high score lives
 * in EEPROM and survives power-off.
 */
public final class SnakeGame {
    public static final byte INS_TICK = (byte) 0x10;   // P1 = direction, 0 keeps the current one
    public static final byte INS_NEW = (byte) 0x20;

    private static final byte EMPTY = 0, BODY = 1, HEAD = 2, FOOD = 3;
    private static final short CELLS = 256;

    private static final byte UP = 1, RIGHT = 2, DOWN = 3, LEFT = 4;

    private static final byte INIT = 0, PLAYING = 1, DEAD = 2, WON = 3;

    // Indices into st[]
    private static final short S_STATE = 0, S_HEAD = 1, S_TAIL = 2, S_LEN = 3,
            S_DIR = 4, S_SCORE = 5, S_FOOD = 6;

    // state(1) score(2) hiscore(2) length(2) board(64, 2 bits per cell)
    public static final short FRAME_LEN = 71;

    private final byte[] board;  // cell type per position
    private final byte[] ring;   // snake positions from tail to head, ring buffer
    private final short[] st;
    private final byte[] rnd;
    private final RandomData rng;
    private short hiScore;

    public SnakeGame() {
        board = JCSystem.makeTransientByteArray(CELLS, JCSystem.CLEAR_ON_DESELECT);
        ring = JCSystem.makeTransientByteArray(CELLS, JCSystem.CLEAR_ON_DESELECT);
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

    private void newGame() {
        Util.arrayFillNonAtomic(board, (short) 0, CELLS, EMPTY);
        // Length 3 on row 8, columns 6..8, heading right
        for (short i = 0; i < 3; i++) {
            ring[i] = (byte) (0x86 + i);
            board[(short) (0x86 + i)] = BODY;
        }
        board[0x88] = HEAD;
        st[S_TAIL] = 0;
        st[S_HEAD] = 2;
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

        short head = (short) (ring[st[S_HEAD]] & 0xFF);
        short x = (short) (head & 0x0F);
        short y = (short) ((short) (head >> 4) & 0x0F);
        switch (dir) {
        case UP:    y--; break;
        case DOWN:  y++; break;
        case LEFT:  x--; break;
        default:    x++; break;
        }
        if (x < 0 || x > 15 || y < 0 || y > 15) {
            gameOver(DEAD);
            return;
        }
        short next = (short) ((short) (y << 4) | x);
        short tail = (short) (ring[st[S_TAIL]] & 0xFF);
        boolean eat = next == st[S_FOOD];

        // The head may move into the cell the tail is leaving.
        if (board[next] == BODY && (eat || next != tail)) {
            gameOver(DEAD);
            return;
        }
        if (!eat) {
            board[tail] = EMPTY;
            st[S_TAIL] = (short) ((short) (st[S_TAIL] + 1) & 0xFF);
        }
        board[head] = BODY;
        board[next] = HEAD;
        st[S_HEAD] = (short) ((short) (st[S_HEAD] + 1) & 0xFF);
        ring[st[S_HEAD]] = (byte) next;

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
            if (board[p] == EMPTY) {
                board[p] = FOOD;
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

    private short writeFrame(byte[] buf) {
        buf[0] = (byte) st[S_STATE];
        Util.setShort(buf, (short) 1, st[S_SCORE]);
        Util.setShort(buf, (short) 3, hiScore);
        Util.setShort(buf, (short) 5, st[S_LEN]);
        // Four cells per byte, first cell in the high bits
        for (short i = 0; i < 64; i++) {
            short c = (short) (i << 2);
            buf[(short) (7 + i)] = (byte) ((short) (board[c] << 6)
                    | (short) (board[(short) (c + 1)] << 4)
                    | (short) (board[(short) (c + 2)] << 2)
                    | board[(short) (c + 3)]);
        }
        return FRAME_LEN;
    }
}
