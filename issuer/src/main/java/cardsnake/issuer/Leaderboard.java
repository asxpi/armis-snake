package cardsnake.issuer;

import org.springframework.stereotype.Component;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** High scores read from cards, one entry per player. In memory only. */
@Component
public class Leaderboard {

    public record Entry(String name, int score) {
    }

    private final Map<String, Entry> entries = new ConcurrentHashMap<>();

    public void record(Player player, int score) {
        entries.merge(player.id(), new Entry(player.name(), score),
                (old, now) -> new Entry(now.name(), Math.max(old.score(), now.score())));
    }

    public void remove(Player player) {
        entries.remove(player.id());
    }

    public List<Entry> top(int limit) {
        return entries.values().stream()
                .sorted(Comparator.comparingInt(Entry::score).reversed().thenComparing(Entry::name))
                .limit(limit)
                .toList();
    }
}
