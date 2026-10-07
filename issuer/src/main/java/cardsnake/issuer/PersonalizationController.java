package cardsnake.issuer;

import cardsnake.issuer.model.AbortedResponse;
import cardsnake.issuer.model.ContinueRequest;
import cardsnake.issuer.model.ContinueResponse;
import cardsnake.issuer.model.RemovedRequest;
import cardsnake.issuer.model.StartRequest;
import cardsnake.issuer.model.StartResponse;
import cardsnake.issuer.model.StoreDataCommand;
import cardsnake.issuer.model.StoreDataResponse;
import cardsnake.issuer.securemessaging.SecureMessagingKeyStore;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.cert.X509Certificate;
import java.util.Optional;

@RestController
@RequiredArgsConstructor
@RequestMapping(
        path = "/v1/personalization",
        consumes = MediaType.APPLICATION_JSON_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE
)
public class PersonalizationController {

    @NonNull
    private final SecureMessagingKeyStore secureMessagingKeyStore;
    @NonNull
    private final PersonalizationService personalizationService;

    @PostMapping(path = "start")
    public ResponseEntity<?> startPersonalization(@RequestBody StartRequest startRequest) {
        X509Certificate cardHolderCertificate = startRequest.getCardHolderCertificate();
        Optional<StoreDataCommand> storeDataCommand;
        try {
            storeDataCommand = personalizationService.startPersonalization(cardHolderCertificate);
        } catch (IssuerAbortedPersonalizationException e) {
            AbortedResponse abortedResponse = new AbortedResponse(e.getReasonCode());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(abortedResponse);
        }

        // Issuer may choose to use secure messaging inside personalization commands and responses. But in any case,
        // Issuer REST API requires always returning an issuer certificate, even when secure messaging is not used.
        X509Certificate issuerCertificate = secureMessagingKeyStore.getIssuerCertificate();
        StartResponse startResponse = new StartResponse(issuerCertificate, storeDataCommand.orElse(null));
        return ResponseEntity.ok(startResponse);
    }

    @PostMapping(path = "continue")
    public ResponseEntity<?> continuePersonalization(@RequestBody ContinueRequest continueRequest) {
        X509Certificate cardHolderCertificate = continueRequest.getCardHolderCertificate();
        StoreDataResponse storeDataResponse = continueRequest.getStoreDataResponse();
        Optional<StoreDataCommand> storeDataCommand;
        try {
            storeDataCommand = personalizationService.continuePersonalization(cardHolderCertificate, storeDataResponse);
        } catch (IssuerAbortedPersonalizationException e) {
            AbortedResponse abortedResponse = new AbortedResponse(e.getReasonCode());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(abortedResponse);
        }
        if (storeDataCommand.isEmpty()) {
            return ResponseEntity.noContent().build();
        }
        ContinueResponse continueResponse = new ContinueResponse(storeDataCommand.get());
        return ResponseEntity.ok(continueResponse);
    }

    @PostMapping(path = "removed")
    public ResponseEntity<Void> removedPersonalization(@RequestBody RemovedRequest removedRequest) {
        personalizationService.removedPersonalization(
                removedRequest.getCardHolderCertificate(),
                removedRequest.getEventType());
        return ResponseEntity.noContent().build();
    }

}
