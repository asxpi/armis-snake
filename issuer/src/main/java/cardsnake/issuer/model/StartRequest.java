package cardsnake.issuer.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import lombok.AllArgsConstructor;
import lombok.NonNull;
import lombok.Value;

import java.security.cert.X509Certificate;

@Value
@AllArgsConstructor(onConstructor_ = @JsonCreator)
public class StartRequest {
    @NonNull
    X509Certificate cardHolderCertificate;
}
