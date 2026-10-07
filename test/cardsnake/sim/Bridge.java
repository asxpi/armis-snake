package cardsnake.sim;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;

/**
 * A personalized ArmisSnake in jCardSim for client/snake.py: deploys the
 * Manager and the applet, personalizes the player name as the issuer, then
 * relays one hex APDU per line on stdin to a hex response on stdout.
 * "#hiscore" runs an issuer session that reads the high score over SM.
 *
 * Usage: Bridge <player name>
 */
public class Bridge {
    public static void main(String[] args) throws Exception {
        // jCardSim prints debug lines to stdout; keep stdout for the protocol
        PrintStream out = System.out;
        System.setOut(new PrintStream(OutputStream.nullOutputStream()));

        ArmisHarness card = new ArmisHarness();
        card.deploy();
        ArmisHarness.expect(ArmisHarness.SW_OK, card.authenticate(card.issuer), "authenticate");
        ArmisHarness.expect(ArmisHarness.SW_OK, card.putName(args.length > 0 ? args[0] : "Player"), "put name");
        System.err.println("ARMIS lifecycle done: Manager deployed, Snake installed and personalized");

        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        for (String line; (line = in.readLine()) != null; ) {
            line = line.trim();
            if (line.equals("#hiscore")) {
                ArmisHarness.expect(ArmisHarness.SW_OK, card.authenticate(card.issuer), "authenticate");
                out.println(card.hiScore());
            } else {
                StringBuilder hex = new StringBuilder();
                for (byte b : card.apdu(line)) {
                    hex.append(String.format("%02x", b));
                }
                out.println(hex);
            }
            out.flush();
        }
    }
}
