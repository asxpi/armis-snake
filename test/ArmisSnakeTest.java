import java.io.OutputStream;
import java.io.PrintStream;
import java.util.Arrays;

/**
 * Lifecycle, game and security tests for ArmisSnake in jCardSim.
 * Exits non-zero on the first failure.
 */
public class ArmisSnakeTest {
    static final String SELECT = "00A4040008F0534E414B454101";
    static final int SW_SECURITY = 0x6982, SW_WRONG_DATA = 0x6A80, SW_WRONG_LENGTH = 0x6700,
            SW_INS = 0x6D00, SW_CLA = 0x6E00;

    static int passed;

    public static void main(String[] args) throws Exception {
        PrintStream out = System.out;
        // jCardSim prints debug lines to stdout
        System.setOut(new PrintStream(OutputStream.nullOutputStream()));

        test(out, "lifecycle: install, finalize, authenticate, personalize", ArmisSnakeTest::lifecycle);
        test(out, "game: start, rules, death, high score", ArmisSnakeTest::game);
        test(out, "issuer reads the high score over SM", ArmisSnakeTest::issuerReadsScore);
        test(out, "rejects install finalized with another key", ArmisSnakeTest::wrongIssuerKey);
        test(out, "rejects INTERNAL AUTHENTICATE signed by another key", ArmisSnakeTest::wrongAuthSigner);
        test(out, "rejects SM commands without a session", ArmisSnakeTest::noSession);
        test(out, "selecting the applet ends the issuer session", ArmisSnakeTest::selectEndsSession);
        test(out, "rejects names over 16 bytes", ArmisSnakeTest::longName);
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

    static ArmisHarness personalized(String name) throws Exception {
        ArmisHarness h = new ArmisHarness();
        h.deploy();
        ArmisHarness.expect(ArmisHarness.SW_OK, h.authenticate(h.issuer), "authenticate");
        ArmisHarness.expect(ArmisHarness.SW_OK, h.putName(name), "put name");
        ArmisHarness.ok(h.apdu(SELECT));
        return h;
    }

    static void lifecycle() throws Exception {
        ArmisHarness h = personalized("Mari-Liis");
        ArmisHarness.expect("Mari-Liis", new String(ArmisHarness.ok(h.apdu("8030000000")), "UTF-8"), "player name");
    }

    /** Frame: state, score, hi, len, then 2-bit cells. */
    static final class Frame {
        int state, score, hi, len;
        int[] cells = new int[256];

        Frame(byte[] f) {
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
    static Frame playToEnd(ArmisHarness h) {
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
        ArmisHarness h = personalized("p");
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

    static void issuerReadsScore() throws Exception {
        ArmisHarness h = personalized("p");
        ArmisHarness.expect(ArmisHarness.SW_OK, h.authenticate(h.issuer), "session");
        ArmisHarness.expect(0, h.hiScore(), "initial high score");
        Frame f = playToEnd(h);
        ArmisHarness.expect(ArmisHarness.SW_OK, h.authenticate(h.issuer), "new session");
        ArmisHarness.expect(f.hi, h.hiScore(), "issuer-read high score");
    }

    static void wrongIssuerKey() throws Exception {
        ArmisHarness h = new ArmisHarness();
        h.deployManager();
        h.install();
        ArmisHarness.expect(SW_WRONG_DATA, h.finalizeInstall(ArmisHarness.generate()), "finalize with other key");
        ArmisHarness.expect(ArmisHarness.SW_OK, h.finalizeInstall(h.issuer), "finalize with issuer key");
    }

    static void wrongAuthSigner() throws Exception {
        ArmisHarness h = new ArmisHarness();
        h.deploy();
        ArmisHarness.expect(SW_SECURITY, h.authenticate(ArmisHarness.generate()), "authenticate with other key");
        h.sessionKey = new byte[32];  // attacker's guess
        ArmisHarness.expect(SW_SECURITY, h.putName("x"), "put name after failed auth");
    }

    static void noSession() throws Exception {
        ArmisHarness h = new ArmisHarness();
        h.deploy();
        h.sessionKey = new byte[32];
        ArmisHarness.expect(SW_SECURITY, h.putName("x"), "put name without session");
    }

    static void selectEndsSession() throws Exception {
        ArmisHarness h = new ArmisHarness();
        h.deploy();
        ArmisHarness.expect(ArmisHarness.SW_OK, h.authenticate(h.issuer), "authenticate");
        ArmisHarness.ok(h.apdu(SELECT));
        ArmisHarness.expect(SW_SECURITY, h.putName("x"), "put name after select");
    }

    static void longName() throws Exception {
        ArmisHarness h = personalized("sixteen-bytes-ok");
        ArmisHarness.expect(ArmisHarness.SW_OK, h.authenticate(h.issuer), "session");
        ArmisHarness.expect(SW_WRONG_LENGTH, h.putName("seventeen-bytes-x"), "17-byte name");
        ArmisHarness.expect("sixteen-bytes-ok", new String(ArmisHarness.ok(h.apdu("8030000000")), "UTF-8"),
                "name unchanged");
    }

    static void unknownCommands() throws Exception {
        ArmisHarness h = personalized("p");
        ArmisHarness.expect(SW_CLA, ArmisHarness.sw(h.apdu("0010000047")), "CLA 00");
        ArmisHarness.expect(SW_INS, ArmisHarness.sw(h.apdu("8099000000")), "INS 99");
        // Issuer commands are only reachable through STORE DATA, not as plain APDUs
        ArmisHarness.expect(SW_INS, ArmisHarness.sw(h.apdu("80CADF0100")), "GET DATA as plain APDU");
    }
}
