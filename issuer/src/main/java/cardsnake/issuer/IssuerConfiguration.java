package cardsnake.issuer;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.jackson.Jackson2ObjectMapperBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

@Configuration
public class IssuerConfiguration {

    /** The issuer certificate returned to ARMIS; the private key is not needed. */
    @Bean
    public X509Certificate issuerCertificate(@Value("${issuer-service.certificate}") Resource certificate)
            throws IOException, CertificateException {
        try (InputStream in = certificate.getInputStream()) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }

    @Bean
    public Jackson2ObjectMapperBuilderCustomizer objectMapperCustomizer() {
        return jacksonObjectMapperBuilder -> jacksonObjectMapperBuilder
                // Forward compatibility for future API versions.
                .featuresToDisable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                // Forward compatibility for future API versions.
                .featuresToEnable(DeserializationFeature.READ_UNKNOWN_ENUM_VALUES_USING_DEFAULT_VALUE)
                // Cleaner output.
                .serializationInclusion(JsonInclude.Include.NON_NULL);
    }
}
