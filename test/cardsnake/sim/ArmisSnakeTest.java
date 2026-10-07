package cardsnake.sim;

import java.io.OutputStream;
import java.io.PrintStream;
import java.util.Arrays;

/**
 * Install, game and rejection tests for ArmisSnake in jCardSim.
 * Exits non-zero on the first failure.
 */
public class ArmisSnakeTest {
    static final String SELECT = "00A4040008F0534E414B454101";
    static final String SELECT_MANAGER = "00A404000A4D616E61676572417070";
    static final int SW_WRONG_DATA = 0x6A80, SW_INS = 0x6D00, SW_CLA = 0x6E00;

    static int passed;

    public static void main(String[] args) throws Exception {
        PrintStream out = System.out;
        // jCardSim prints debug lines to stdout
        System.setOut(new PrintStream(OutputStream.nullOutputStream()));

        test(out, "install: register with the Manager, finalize with the issuer key", ArmisSnakeTest::install);
        test(out, "game: start, rules, death, high score", ArmisSnakeTest::game);
        test(out, "high score stays on the card; game state does not", ArmisSnakeTest::highScorePersists);
        test(out, "rejects install finalized with another key", ArmisSnakeTest::wrongIssuerKey);
        test(out, "rejects STORE DATA after the install", ArmisSnakeTest::noPersonalization);
        test(out, "rejects unknown CLA and INS", ArmisSnakeTest::unknownCommands);
        out.println(passed + " tests passed");
    }

    interface Body {
        void run() throws Exception;
    }

    static void test(PrintStream out, String name, Body body) {
        try {
            body.run();
            passed++;
            out.println("ok   " + name);
        } catch (Throwable t) {
            out.println("FAIL " + name);
            t.printStackTrace(out);
            System.exit(1);
        }
    }

    /** ArmisSnake installed through ARMIS and selected. */
    static ArmisHarness installed() throws Exception {
        ArmisHarness h = new ArmisHarness();
        h.deploy();
        ArmisHarness.ok(h.apdu(SELECT));
        return h;
    }

    static void install() throws Exception {
        Frame f = cmd(installed(), 0x20, 0);
        ArmisHarness.expect(1, f.state, "new game after install");
    }

    /** Frame: state, score, hi, len, then 2-bit cells. */
    public static final class Frame {
        public int state, score, hi, len;
        public int[] cells = new int[256];

        public Frame(byte[] f) {
            ArmisHarness.expect(71, f.length, "frame length");
            state = f[0];
            score = ((f[1] & 0xFF) << 8) | (f[2] & 0xFF);
            hi = ((f[3] & 0xFF) << 8) | (f[4] & 0xFF);
            len = ((f[5] & 0xFF) << 8) | (f[6] & 0xFF);
            for (int i = 0; i < 256; i++) {
                cells[i] = (f[7 + i / 4] >> (6 - 2 * (i % 4))) & 3;
            }
        }

        int find(int type) {
            for (int i = 0; i < 256; i++) {
                if (cells[i] == type) {
                    return i;
                }
            }
            return -1;
        }

        long count(int type) {
            return Arrays.stream(cells).filter(c -> c == type).count();
        }
    }

    static Frame cmd(ArmisHarness h, int ins, int p1) {
        return new Frame(ArmisHarness.ok(h.apdu(String.format("80%02X%02X0047", ins, p1))));
    }

    /** Plays greedily towards the food until the game ends; returns the last frame. */
    public static Frame playToEnd(ArmisHarness h) {
        Frame f = cmd(h, 0x20, 0);
        for (int n = 0; n < 5000 && f.state == 1; n++) {
            int head = f.find(2), food = f.find(3);
            int hx = head & 15, hy = head >> 4, fx = food & 15, fy = food >> 4;
            int[] want = {fx > hx ? 2 : 0, fx < hx ? 4 : 0, fy > hy ? 3 : 0, fy < hy ? 1 : 0, 1, 2, 3, 4};
            int dir = 1;
            for (int d : want) {
                if (d != 0 && safe(f, hx, hy, d)) {
                    dir = d;
                    break;
                }
            }
            int eaten = f.score;
            f = cmd(h, 0x10, dir);
            // The board stores the snake as directions the tail follows; it must stay whole
            ArmisHarness.expect((long) f.len, f.count(1) + f.count(2), "snake cells after a move");
            ArmisHarness.expect(1L, f.count(2), "one head");
            if (f.state == 1 && f.score > eaten) {
                ArmisHarness.expect(3 + f.score / 10, f.len, "length after eating");
            }
        }
        return f;
    }

    static boolean safe(Frame f, int x, int y, int d) {
        x += d == 2 ? 1 : d == 4 ? -1 : 0;
        y += d == 3 ? 1 : d == 1 ? -1 : 0;
        return x >= 0 && x < 16 && y >= 0 && y < 16 && (f.cells[y * 16 + x] == 0 || f.cells[y * 16 + x] == 3);
    }

    static void game() throws Exception {
        ArmisHarness h = installed();
        Frame f = cmd(h, 0x20, 0);
        ArmisHarness.expect(1, f.state, "state");
        ArmisHarness.expect(3, f.len, "length");
        ArmisHarness.expect(0x88, f.find(2), "head");
        ArmisHarness.expect(2L, f.count(1), "body cells");
        ArmisHarness.expect(1L, f.count(3), "food");

        f = cmd(h, 0x10, 4);  // left = straight back into the neck, ignored
        ArmisHarness.expect(0x89, f.find(2), "head after reverse attempt");

        f = playToEnd(h);
        ArmisHarness.expect(2, f.state, "dead");
        ArmisHarness.expect(f.score, f.hi, "high score");
        ArmisHarness.expect((long) f.len, f.count(1) + f.count(2), "snake cells");
        if (f.score == 0) {
            throw new AssertionError("greedy player ate nothing");
        }

        Frame g = cmd(h, 0x20, 0);
        ArmisHarness.expect(f.hi, g.hi, "high score kept on new game");
        ArmisHarness.expect(0, g.score, "score reset");
    }

    static void highScorePersists() throws Exception {
        ArmisHarness h = installed();
        Frame end = playToEnd(h);
        // Selecting another applet clears the game; the high score is in EEPROM
        ArmisHarness.ok(h.apdu(SELECT_MANAGER));
        ArmisHarness.ok(h.apdu(SELECT));
        Frame f = cmd(h, 0x10, 0);
        ArmisHarness.expect(1, f.state, "a fresh game after reselection");
        ArmisHarness.expect(3, f.len, "fresh length");
        ArmisHarness.expect(end.hi, f.hi, "high score after reselection");
    }

    static void wrongIssuerKey() throws Exception {
        ArmisHarness h = new ArmisHarness();
        h.deployManager();
        h.install();
        ArmisHarness.expect(SW_WRONG_DATA, h.finalizeInstall(ArmisHarness.generate()), "finalize with other key");
        ArmisHarness.expect(ArmisHarness.SW_OK, h.finalizeInstall(h.issuer), "finalize with issuer key");
    }

    static void noPersonalization() throws Exception {
        ArmisHarness h = new ArmisHarness();
        h.deploy();
        byte[] command = ArmisHarness.hex("DA5F200141");
        ArmisHarness.expect(SW_INS, ArmisHarness.sw(h.storeData(ArmisHarness.SNAKE_AID, 0x80, command)), "STORE DATA");
    }

    static void unknownCommands() throws Exception {
        ArmisHarness h = installed();
        ArmisHarness.expect(SW_CLA, ArmisHarness.sw(h.apdu("0010000047")), "CLA 00");
        ArmisHarness.expect(SW_INS, ArmisHarness.sw(h.apdu("8099000000")), "INS 99");
        ArmisHarness.expect(SW_INS, ArmisHarness.sw(h.apdu("8030000000")), "INS 30");
    }
}
