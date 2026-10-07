package cardsnake.issuer.securemessaging;

import cardsnake.issuer.helpers.validation.ResourceExists;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

@Getter
@Setter
@Validated
@Configuration
@ConfigurationProperties(prefix = "issuer-service.secure-messaging")
public class SecureMessagingKeyStoreConfigurationProvider {

    private static final String DEFAULT_KEYSTORE_TYPE = "PKCS12";

    @NotNull
    @ResourceExists
    private Resource keyStore;
    @NotNull
    private char[] keyStorePassword;
    @NotBlank
    private String keyStoreType = DEFAULT_KEYSTORE_TYPE;
    @NotBlank
    private String keyAlias;
    @NotNull
    private char[] keyPassword;

}
