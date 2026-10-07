package cardsnake.issuer.model;

import lombok.NonNull;
import lombok.Value;

import java.security.cert.X509Certificate;

@Value
public class RemovedRequest {
    @NonNull
    X509Certificate cardHolderCertificate;
    @NonNull
    PersonalizationRemovedEventType eventType;
}
