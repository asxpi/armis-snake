package cardsnake.issuer.securemessaging;

import lombok.Getter;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Objects;

@Slf4j
@Component
public class SecureMessagingKeyStore {

    @Getter
    private final PrivateKey issuerPrivateKey;
    @Getter
    private final X509Certificate issuerCertificate;

    public SecureMessagingKeyStore(@NonNull SecureMessagingKeyStoreConfigurationProvider configurationProvider) {
        log.info("Initializing secure messaging context with key alias '{}' from {}",
                configurationProvider.getKeyAlias(),
                configurationProvider.getKeyStore()
        );
        KeyStore keyStore = loadKeyStore(
                configurationProvider.getKeyStore(),
                configurationProvider.getKeyStorePassword(),
                configurationProvider.getKeyStoreType());
        issuerPrivateKey = getPrivateKey(keyStore,
                configurationProvider.getKeyAlias(),
                configurationProvider.getKeyPassword());
        issuerCertificate = getCertificate(keyStore, configurationProvider.getKeyAlias());
    }

    private static KeyStore loadKeyStore(Resource keyStoreResource, char[] password, String type) {
        try {
            KeyStore keyStore = KeyStore.getInstance(type);
            try (InputStream in = keyStoreResource.getInputStream()) {
                keyStore.load(in, password);
            }
            return keyStore;
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Failed to initialize key-store: " + type, e);
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException("Failed to load key-store: " + keyStoreResource.getDescription(), e);
        }
    }

    private static PrivateKey getPrivateKey(KeyStore keyStore, String alias, char[] password) {
        try {
            return (PrivateKey) Objects.requireNonNull(
                    keyStore.getKey(alias, password),
                    "Key not found: " + alias
            );
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to recover key: " + alias, e);
        }
    }

    private static X509Certificate getCertificate(KeyStore keyStore, String alias) {
        try {
            return (X509Certificate) Objects.requireNonNull(
                    keyStore.getCertificate(alias),
                    "Certificate not found: " + alias);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to extract certificate chain: " + alias, e);
        }
    }

}
