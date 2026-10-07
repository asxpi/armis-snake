package cardsnake.issuer;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class LeaderboardController {

    @NonNull
    private final Leaderboard leaderboard;

    @GetMapping(path = "/v1/leaderboard", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<Leaderboard.Entry> leaderboard(@RequestParam(defaultValue = "10") int limit) {
        return leaderboard.top(Math.max(1, Math.min(limit, 100)));
    }
}
