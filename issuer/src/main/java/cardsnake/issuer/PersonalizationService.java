package cardsnake.issuer;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import cardsnake.issuer.model.PersonalizationRemovedEventType;
import cardsnake.issuer.model.StoreDataCommand;
import cardsnake.issuer.model.StoreDataResponse;
import cardsnake.issuer.securemessaging.SecureMessagingKeyStore;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class PersonalizationService {

    @NonNull
    private final SecureMessagingKeyStore secureMessagingKeyStore;
    @NonNull
    private final SecureRandom secureRandom;
    @NonNull
    private final Leaderboard leaderboard;

    private final Cache<X509Certificate, PersonalizationSession> sessions = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofHours(25))
            .build();

    public Optional<StoreDataCommand> startPersonalization(X509Certificate cardHolderCertificate) {
        PersonalizationSession session = new PersonalizationSession(secureMessagingKeyStore, secureRandom, cardHolderCertificate, leaderboard);
        PersonalizationSession oldSession = sessions.asMap().put(cardHolderCertificate, session);
        // TODO If oldSession != null, wait for running request to finish.
        // Release resources on oldSession if necessary.

        synchronized (session) {
            return session.startPersonalization();
        }
    }

    public Optional<StoreDataCommand> continuePersonalization(
            X509Certificate cardHolderCertificate,
            StoreDataResponse previousStoreDataResponse) {
        PersonalizationSession session = sessions.getIfPresent(cardHolderCertificate);
        if (session == null) {
            throw new RuntimeException("Personalization session not found for card holder certificate: " + cardHolderCertificate);
        }
        synchronized (session) {
            return session.continuePersonalization(previousStoreDataResponse);
        }
    }

    public void removedPersonalization(X509Certificate cardHolderCertificate, PersonalizationRemovedEventType eventType) {
        PersonalizationSession oldSession = sessions.asMap().remove(cardHolderCertificate);
        // The applet is gone from the card, so is the player's entry
        leaderboard.remove(Player.of(cardHolderCertificate));
        // TODO If oldSession != null, wait for running request to finish.
        // Release resources on oldSession if necessary.
    }

}
