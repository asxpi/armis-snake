package cardsnake.sim;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;

/**
 * ArmisSnake installed through ARMIS in jCardSim, for client/snake.py: relays
 * one hex APDU per line on stdin to a hex response (data + SW) on stdout.
 */
public class Bridge {
    public static void main(String[] args) throws Exception {
        // jCardSim prints debug lines to stdout; keep stdout for the protocol
        PrintStream out = System.out;
        System.setOut(new PrintStream(OutputStream.nullOutputStream()));

        ArmisHarness card = new ArmisHarness();
        card.deploy();

        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        for (String line; (line = in.readLine()) != null; ) {
            StringBuilder hex = new StringBuilder();
            for (byte b : card.apdu(line.trim())) {
                hex.append(String.format("%02x", b));
            }
            out.println(hex);
            out.flush();
        }
    }
}
