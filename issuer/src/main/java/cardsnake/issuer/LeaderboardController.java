package cardsnake.issuer;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/** Endpoints for game UIs; see docs/API.md. Binary fields are Base64 in JSON. */
@RestController
@RequiredArgsConstructor
@RequestMapping(path = "/v1", produces = MediaType.APPLICATION_JSON_VALUE)
public class LeaderboardController {

    public record Challenge(byte[] nonce) {
    }

    public record ScoreSubmission(byte[] nonce, byte[] signedScore) {
    }

    @NonNull
    private final Leaderboard leaderboard;
    @NonNull
    private final Challenges challenges;
    @NonNull
    private final Scores scores;

    @GetMapping("/leaderboard")
    public List<Leaderboard.Entry> leaderboard(@RequestParam(defaultValue = "10") int limit) {
        return leaderboard.top(Math.max(1, Math.min(limit, 100)));
    }

    @GetMapping("/challenge")
    public Challenge challenge() {
        return new Challenge(challenges.issue());
    }

    @PostMapping(path = "/scores", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Leaderboard.Entry> submit(@RequestBody ScoreSubmission submission) {
        if (submission.nonce() == null || submission.signedScore() == null) {
            return ResponseEntity.badRequest().build();
        }
        return scores.submit(submission.nonce(), submission.signedScore())
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.status(HttpStatus.FORBIDDEN).build());
    }
}
