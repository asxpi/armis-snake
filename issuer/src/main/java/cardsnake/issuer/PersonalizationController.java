package cardsnake.issuer;

import cardsnake.issuer.model.AbortedResponse;
import cardsnake.issuer.model.RemovedRequest;
import cardsnake.issuer.model.StartRequest;
import cardsnake.issuer.model.StartResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.cert.X509Certificate;

/**
 * The ARMIS issuer API (issuer-openapi.yml) for an applet that needs no
 * personalization: every install is allowed, and the issuer sends no commands.
 */
@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping(
        path = "/v1/personalization",
        consumes = MediaType.APPLICATION_JSON_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE
)
public class PersonalizationController {

    @NonNull
    private final X509Certificate issuerCertificate;

    @PostMapping(path = "start")
    public StartResponse startPersonalization(@RequestBody StartRequest startRequest) {
        return new StartResponse(issuerCertificate);
    }

    /** Only follows a command from the issuer, which never sends one; abort if called anyway. */
    @PostMapping(path = "continue")
    public ResponseEntity<AbortedResponse> continuePersonalization() {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new AbortedResponse(null));
    }

    @PostMapping(path = "removed")
    public ResponseEntity<Void> removedPersonalization(@RequestBody RemovedRequest removedRequest) {
        log.info("Applet removed: {}", removedRequest.getEventType());
        return ResponseEntity.noContent().build();
    }
}
