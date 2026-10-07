package cardsnake.issuer;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.HexFormat;

/** Single-use nonces for score submissions, so a signed score cannot be replayed. */
@Component
@RequiredArgsConstructor
public class Challenges {

    static final int NONCE_LENGTH = 32;
    static final Duration LIFETIME = Duration.ofMinutes(2);

    @NonNull
    private final SecureRandom secureRandom;

    private final Cache<String, Boolean> issued = Caffeine.newBuilder()
            .expireAfterWrite(LIFETIME)
            .maximumSize(100_000)
            .build();

    public byte[] issue() {
        byte[] nonce = new byte[NONCE_LENGTH];
        secureRandom.nextBytes(nonce);
        issued.put(HexFormat.of().formatHex(nonce), Boolean.TRUE);
        return nonce;
    }

    /** True the first time an issued, unexpired nonce is redeemed; false otherwise. */
    public boolean redeem(byte[] nonce) {
        return nonce.length == NONCE_LENGTH && issued.asMap().remove(HexFormat.of().formatHex(nonce)) != null;
    }
}
