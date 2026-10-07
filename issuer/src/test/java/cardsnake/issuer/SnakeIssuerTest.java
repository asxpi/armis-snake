package cardsnake.issuer;

import cardsnake.sim.ArmisHarness;
import cardsnake.sim.ArmisSnakeTest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.io.ByteArrayInputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Plays the ARMIS server against this service over its REST API, relaying
 * every STORE DATA to ArmisSnake and the ARMIS Manager applet in jCardSim.
 */
@SpringBootTest
@AutoConfigureMockMvc
class SnakeIssuerTest {

    static final KeyPair ISSUER = ArmisHarness.generate();
    static final KeyPair ARMIS_CA = ArmisHarness.generate();
    static final String SELECT = "00A4040008F0534E414B454101";

    @DynamicPropertySource
    static void issuerKeyStore(DynamicPropertyRegistry registry) throws Exception {
        X509Certificate cert = certificate("CN=Snake issuer", ISSUER.getPublic(), "CN=Snake issuer", ISSUER.getPrivate());
        char[] password = "test".toCharArray();
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("issuer-service", ISSUER.getPrivate(), password, new Certificate[] {cert});
        Path file = Files.createTempFile("issuer", ".p12");
        file.toFile().deleteOnExit();
        try (OutputStream out = Files.newOutputStream(file)) {
            keyStore.store(out, password);
        }
        registry.add("issuer-service.secure-messaging.key-store", () -> "file:" + file);
        registry.add("issuer-service.secure-messaging.key-store-password", () -> "test");
        registry.add("issuer-service.secure-messaging.key-password", () -> "test");
    }

    @Autowired
    MockMvc mvc;
    @Autowired
    ObjectMapper json;
    @Autowired
    Leaderboard leaderboard;

    ArmisHarness card;
    X509Certificate holder;

    @BeforeEach
    void card() throws Exception {
        card = new ArmisHarness(new KeyPair(ISSUER.getPublic(), null));
        card.deployManager();
        // ARMIS CA certifies the Manager's card key; the subject carries the holder's identity
        holder = certificate("C=EE,SERIALNUMBER=PNOEE-38001085718,GIVENNAME=MARI-LIIS,SURNAME=TAMM,"
                + "CN=TAMM\\,MARI-LIIS\\,38001085718", card.managerKey, "CN=Test ARMIS CA", ARMIS_CA.getPrivate());
        leaderboard.remove(Player.of(holder));
    }

    @Test
    void personalizesNameAndRecordsScore() throws Exception {
        personalize(true);
        ArmisHarness.ok(card.apdu(SELECT));
        assertEquals("Mari-Liis", new String(ArmisHarness.ok(card.apdu("8030000000")), StandardCharsets.UTF_8));
        assertEquals("[{\"name\":\"Mari-Liis\",\"score\":0}]", leaderboardJson());
    }

    @Test
    void nextPersonalizationReadsPlayedScore() throws Exception {
        personalize(true);
        ArmisHarness.ok(card.apdu(SELECT));
        ArmisSnakeTest.Frame end = ArmisSnakeTest.playToEnd(card);
        assertTrue(end.hi > 0, "player scored");

        personalize(false);
        assertEquals("[{\"name\":\"Mari-Liis\",\"score\":" + end.hi + "}]", leaderboardJson());
    }

    @Test
    void removedDropsPlayer() throws Exception {
        personalize(true);
        String body = json.writeValueAsString(Map.of(
                "cardHolderCertificate", b64(holder.getEncoded()), "eventType", "UNINSTALLED_BY_USER"));
        assertEquals(204, call("/v1/personalization/removed", body).getResponse().getStatus());
        assertEquals("[]", leaderboardJson());
    }

    @Test
    void playerFromCertificate() {
        assertEquals("Mari-Liis", Player.titleCase("MARI-LIIS"));
        assertEquals("Jaan Peeter", Player.titleCase("JAAN PEETER"));
        assertEquals("Ülle-Õnne Mäe", Player.fit("Ülle-Õnne Mäesalu"));
        Player p = Player.of(holder);
        assertEquals("Mari-Liis", p.name());
        assertTrue(!p.id().contains("38001085718"), "personal code is hashed");
    }

    /** What the ARMIS server does: start, install and finalize once, then relay STORE DATA until done. */
    void personalize(boolean install) throws Exception {
        JsonNode r = json.readTree(call("/v1/personalization/start", holderJson(null)).getResponse().getContentAsByteArray());
        X509Certificate issuerCert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(r.get("issuerCertificate").binaryValue()));
        assertArrayEquals(ISSUER.getPublic().getEncoded(), issuerCert.getPublicKey().getEncoded());
        if (install) {
            card.install();
            assertEquals(ArmisHarness.SW_OK, card.finalizeInstall(new KeyPair(issuerCert.getPublicKey(), null)));
        }

        JsonNode command = r.get("storeDataCommand");
        while (command != null) {
            int p1 = (command.get("last").asBoolean() ? 0x80 : 0) | (command.get("responseExpected").asBoolean() ? 1 : 0);
            byte[] response = card.storeData(ArmisHarness.SNAKE_AID, p1, command.get("data").binaryValue());
            Map<String, Object> storeDataResponse = Map.of(
                    "statusWord", ArmisHarness.sw(response),
                    "data", b64(Arrays.copyOf(response, response.length - 2)));
            MvcResult next = call("/v1/personalization/continue", holderJson(storeDataResponse));
            command = next.getResponse().getStatus() == 204 ? null
                    : json.readTree(next.getResponse().getContentAsByteArray()).get("storeDataCommand");
        }
    }

    String holderJson(Map<String, Object> storeDataResponse) throws Exception {
        return storeDataResponse == null
                ? json.writeValueAsString(Map.of("cardHolderCertificate", b64(holder.getEncoded())))
                : json.writeValueAsString(Map.of("cardHolderCertificate", b64(holder.getEncoded()),
                        "storeDataResponse", storeDataResponse));
    }

    MvcResult call(String path, String body) throws Exception {
        MvcResult result = mvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).content(body)).andReturn();
        int status = result.getResponse().getStatus();
        assertTrue(status == 200 || status == 204, path + " returned " + status);
        return result;
    }

    String leaderboardJson() throws Exception {
        return mvc.perform(get("/v1/leaderboard")).andReturn().getResponse().getContentAsString();
    }

    static String b64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    static X509Certificate certificate(String subject, PublicKey key, String issuer, PrivateKey signer) throws Exception {
        Instant now = Instant.now();
        var builder = new JcaX509v3CertificateBuilder(new X500Name(BCStyle.INSTANCE, issuer),
                BigInteger.valueOf(now.toEpochMilli()), Date.from(now.minus(Duration.ofDays(1))),
                Date.from(now.plus(Duration.ofDays(365))), new X500Name(BCStyle.INSTANCE, subject), key);
        return new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA384withECDSA").build(signer)));
    }
}
