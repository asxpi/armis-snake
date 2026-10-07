package cardsnake.issuer;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/** The ARMIS issuer API as the ARMIS server calls it, with the repository's issuer.crt. */
@SpringBootTest
@AutoConfigureMockMvc
class SnakeIssuerTest {

    @Autowired
    MockMvc mvc;
    @Autowired
    ObjectMapper json;

    static byte[] issuerCertificate() throws Exception {
        try (var in = Files.newInputStream(Path.of("issuer.crt"))) {
            return CertificateFactory.getInstance("X.509").generateCertificate(in).getEncoded();
        }
    }

    /** Any certificate will do as the card holder's; the service does not look at it. */
    String holder() throws Exception {
        return Base64.getEncoder().encodeToString(issuerCertificate());
    }

    MvcResult call(String path, Map<String, Object> body) throws Exception {
        return mvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(body)))
                .andReturn();
    }

    @Test
    void startReturnsIssuerCertificateAndNoCommand() throws Exception {
        MvcResult r = call("/v1/personalization/start", Map.of("cardHolderCertificate", holder()));
        assertEquals(200, r.getResponse().getStatus());
        var body = json.readTree(r.getResponse().getContentAsByteArray());
        assertArrayEquals(issuerCertificate(), body.get("issuerCertificate").binaryValue());
        assertFalse(body.has("storeDataCommand"), "no personalization command");
    }

    @Test
    void continueAborts() throws Exception {
        MvcResult r = call("/v1/personalization/continue", Map.of("cardHolderCertificate", holder(),
                "storeDataResponse", Map.of("statusWord", 0x9000, "data", "")));
        assertEquals(403, r.getResponse().getStatus());
    }

    @Test
    void removedIsAcknowledged() throws Exception {
        MvcResult r = call("/v1/personalization/removed", Map.of("cardHolderCertificate", holder(),
                "eventType", "UNINSTALLED_BY_USER"));
        assertEquals(204, r.getResponse().getStatus());
    }
}
