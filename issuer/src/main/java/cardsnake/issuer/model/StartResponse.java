package cardsnake.issuer.model;

import lombok.NonNull;
import lombok.Value;

import java.security.cert.X509Certificate;

/** No storeDataCommand: the applet needs no personalization. */
@Value
public class StartResponse {
    @NonNull
    X509Certificate issuerCertificate;
}
