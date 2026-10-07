package cardsnake.issuer.helpers.json;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import org.springframework.boot.jackson.JsonComponent;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

@JsonComponent
public class X509CertificateSerializer extends StdSerializer<X509Certificate> {

    public X509CertificateSerializer() {
        super(X509Certificate.class);
    }

    @Override
    public void serialize(X509Certificate x509Certificate, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
        byte[] derEncodedX509Certificate;
        try {
            derEncodedX509Certificate = x509Certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new IOException("Failed to encode X.509 certificate to ASN.1 DER", e);
        }
        jsonGenerator.writeBinary(derEncodedX509Certificate);
    }

}
