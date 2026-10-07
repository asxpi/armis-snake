package cardsnake.issuer;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.autoconfigure.jackson.Jackson2ObjectMapperBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import java.security.SecureRandom;
import java.security.Security;

@Configuration
public class IssuerConfiguration {

    @PostConstruct
    public void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @PreDestroy
    public void cleanUp() {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

    @Bean
    public SecureRandom secureRandom() {
        return new SecureRandom();
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
