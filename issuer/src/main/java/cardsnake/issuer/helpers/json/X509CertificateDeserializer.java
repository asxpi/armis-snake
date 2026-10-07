package cardsnake.issuer.helpers.json;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import org.springframework.boot.jackson.JsonComponent;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

@JsonComponent
public class X509CertificateDeserializer extends StdDeserializer<X509Certificate> {

    public X509CertificateDeserializer() {
        super(X509Certificate.class);
    }

    @Override
    public X509Certificate deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException {
        byte[] derEncodedX509Certificate = jsonParser.getBinaryValue();
        try (InputStream inputStream = new ByteArrayInputStream(derEncodedX509Certificate)) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certificateFactory.generateCertificate(inputStream);
        } catch (CertificateException e) {
            throw new IOException("Failed to decode X.509 certificate from ASN.1 DER", e);
        }
    }

}
