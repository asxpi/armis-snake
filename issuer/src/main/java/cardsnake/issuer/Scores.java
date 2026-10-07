package cardsnake.issuer;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Optional;

/**
 * Checks scores signed by cards (SIGN SCORE, docs/API.md) and records them.
 * The card signs CONTEXT || player id || nonce || high score with its ARMIS
 * key; a host only relays the response, so it cannot change the score.
 */
@Component
@RequiredArgsConstructor
public class Scores {

    static final byte[] CONTEXT = "armis-snake score".getBytes(StandardCharsets.US_ASCII);

    @NonNull
    private final Challenges challenges;
    @NonNull
    private final Players players;
    @NonNull
    private final Leaderboard leaderboard;

    /**
     * @param nonce       a nonce from {@link Challenges#issue()}, consumed by this call
     * @param signedScore the card's SIGN SCORE response: player id (16) || score (2) || ECDSA signature
     * @return the player's leaderboard entry, or empty if the submission is rejected
     */
    public Optional<Leaderboard.Entry> submit(byte[] nonce, byte[] signedScore) {
        if (!challenges.redeem(nonce) || signedScore.length <= Player.ID_LENGTH + 2) {
            return Optional.empty();
        }
        byte[] id = Arrays.copyOf(signedScore, Player.ID_LENGTH);
        byte[] score = Arrays.copyOfRange(signedScore, Player.ID_LENGTH, Player.ID_LENGTH + 2);
        byte[] signature = Arrays.copyOfRange(signedScore, Player.ID_LENGTH + 2, signedScore.length);

        Optional<Player> player = players.byId(HexFormat.of().formatHex(id));
        if (player.isEmpty() || !verify(player.get(), id, nonce, score, signature)) {
            return Optional.empty();
        }
        return Optional.of(leaderboard.record(player.get(), ((score[0] & 0xFF) << 8) | (score[1] & 0xFF)));
    }

    private static boolean verify(Player player, byte[] id, byte[] nonce, byte[] score, byte[] signature) {
        ByteArrayOutputStream message = new ByteArrayOutputStream();
        message.writeBytes(CONTEXT);
        message.writeBytes(id);
        message.writeBytes(nonce);
        message.writeBytes(score);
        try {
            Signature verifier = Signature.getInstance("SHA384withECDSA");
            verifier.initVerify(player.cardKey());
            verifier.update(message.toByteArray());
            return verifier.verify(signature);
        } catch (GeneralSecurityException e) {
            // Malformed signature
            return false;
        }
    }
}
