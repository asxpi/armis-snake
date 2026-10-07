package cardsnake.issuer;

import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** Players whose card was personalized, by id and by certificate fingerprint. In memory only. */
@Component
public class Players {

    private final Map<String, Player> byId = new ConcurrentHashMap<>();
    private final Map<String, Player> byCertificate = new ConcurrentHashMap<>();

    /** Registers a newly personalized card; returns the player of an earlier install it replaces. */
    public synchronized Optional<Player> register(Player player) {
        Optional<Player> replaced = removeByCertificate(player.certificate());
        byId.put(player.id(), player);
        byCertificate.put(player.certificate(), player);
        return replaced;
    }

    public Optional<Player> byId(String id) {
        return Optional.ofNullable(byId.get(id));
    }

    public synchronized Optional<Player> removeByCertificate(String certificate) {
        Player player = byCertificate.remove(certificate);
        if (player != null) {
            byId.remove(player.id());
        }
        return Optional.ofNullable(player);
    }
}
