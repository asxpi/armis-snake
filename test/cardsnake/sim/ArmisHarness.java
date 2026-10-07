package cardsnake.sim;

import cardsnake.ArmisSnake;
import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.base.SimulatorRuntime;
import com.licel.jcardsim.utils.AIDUtil;
import ee.openeid.armis.applet.ecosystem.ManagerApplet;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import javacard.framework.ISOException;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.globalplatform.Personalization;

/**
 * Plays the off-card ARMIS roles against jCardSim: ARMIS (Manager
 * personalization, install, STORE DATA routing) and the issuer service
 * (signed ECDHE, secure messaging), following armis-cli and
 * armis-test-client-issuer-service.
 *
 * Differences from a real card: STORE DATA calls processData() directly
 * instead of going through a GlobalPlatform security domain, and the Manager
 * certificate is a DER stand-in holding its public key instead of an ARMIS
 * CA X.509 certificate, and jCardSim's key generation is deterministic, so
 * every simulated card has the same card key. SM MACs are zero, as in the
 * ARMIS reference code.
 */
public class ArmisHarness {
    public static final byte[] MANAGER_AID = hex("4D616E61676572417070");
    public static final byte[] SNAKE_AID = hex("F0534E414B454101");
    public static final int SW_OK = 0x9000;
    static final int POINT_LEN = 97, FIELD_LEN = 48;

    /** Exposes installed applets so STORE DATA can reach processData(). */
    static class Runtime extends SimulatorRuntime {
        short storeData(byte[] aid, byte[] apdu, int length) {
            activateSimulatorRuntimeInstance();
            Personalization app = (Personalization) getApplet(AIDUtil.create(aid));
            return app.processData(apdu, (short) 0, (short) length, apdu, (short) 0);
        }
    }

    final Runtime rt = new Runtime();
    final Simulator sim = new Simulator(rt);
    final KeyPair issuer;
    /** The Manager applet's card key; ARMIS CA certifies it in production. */
    public ECPublicKey managerKey;
    byte[] sessionKey;
    int sequence;

    public ArmisHarness() {
        this(generate());
    }

    /** issuer: the issuer service's key pair; only its public half goes to the card. */
    public ArmisHarness(KeyPair issuer) {
        this.issuer = issuer;
    }

    // --- ARMIS ---

    /** armis-cli deploy-manager: install, set curve, generate card key, store certificate. */
    public void deployManager() throws GeneralSecurityException {
        sim.installApplet(AIDUtil.create(MANAGER_AID), ManagerApplet.class, lv(MANAGER_AID), (short) 0,
                (byte) (MANAGER_AID.length + 1));

        ECParameterSpec curve = ((ECPublicKey) issuer.getPublic()).getParams();
        byte[] p = fixed(((ECFieldFp) curve.getCurve().getField()).getP());
        byte[] a = fixed(curve.getCurve().getA());
        byte[] b = fixed(curve.getCurve().getB());
        ok(storeData(MANAGER_AID, 0x00, nested(0xDB, 0x7F, 0x49, concat(tlv(0x81, p), tlv(0x82, a), tlv(0x83, b)))));
        ok(storeData(MANAGER_AID, 0x00, nested(0xDB, 0x7F, 0x49, concat(tlv(0x84, point(curve.getGenerator())),
                tlv(0x85, fixed(curve.getOrder())), tlv(0x87, new byte[] {(byte) curve.getCofactor()})))));

        // Response: 7F49 L 86 L <public point>
        byte[] r = ok(storeData(MANAGER_AID, 0x01, nested(0x47, 0, 0, new byte[0])));
        byte[] w = Arrays.copyOfRange(r, 5, 5 + (r[4] & 0xFF));
        managerKey = publicKey(w, curve);

        byte[] cert = tlv(0x30, tlv(0x04, w));
        ok(storeData(MANAGER_AID, 0x80, nested(0xDB, 0x7F, 0x21, concat(tlv(0x02, new byte[] {0}), tlv(0x04, cert)))));
    }

    /** armis-cli deploy-client, first half: install with the Manager AID and the issuer key hash. */
    public void install() throws GeneralSecurityException {
        byte[] hash = MessageDigest.getInstance("SHA-384").digest(issuerPoint(issuer));
        byte[] params = concat(lv(SNAKE_AID), lv(new byte[] {0}), lv(concat(lv(MANAGER_AID), lv(hash))));
        sim.installApplet(AIDUtil.create(SNAKE_AID), ArmisSnake.class, params, (short) 0, (byte) params.length);
    }

    /** Second half: STORE DATA with the issuer public key; returns the SW. */
    public int finalizeInstall(KeyPair key) {
        return sw(storeData(SNAKE_AID, 0x80, issuerPoint(key)));
    }

    void deploy() throws GeneralSecurityException {
        deployManager();
        install();
        expect(SW_OK, finalizeInstall(issuer), "finalize install");
    }

    // --- Issuer service ---

    /**
     * INTERNAL AUTHENTICATE with an ephemeral key signed by signer. On success,
     * checks the card's signature with the Manager key and derives the AES-256
     * session key with ConcatKDF(SHA-384). Returns the SW.
     */
    int authenticate(KeyPair signer) throws GeneralSecurityException {
        KeyPair eph = generate();
        byte[] ephPoint = point(((ECPublicKey) eph.getPublic()).getW());
        Signature s = Signature.getInstance("SHA384withECDSA");
        s.initSign(signer.getPrivate());
        s.update(ephPoint);
        byte[] r = storeData(SNAKE_AID, 0x01, nested(0x88, 0, 0, tlv(0x30, concat(tlv(0x04, ephPoint), s.sign()))));
        if (sw(r) != SW_OK) {
            return sw(r);
        }

        // SEQUENCE { OCTET STRING card ephemeral point, SEQUENCE signature }
        Tlv seq = Tlv.parse(r, 0);
        Tlv cardPoint = Tlv.parse(seq.value, 0);
        Signature v = Signature.getInstance("SHA384withECDSA");
        v.initVerify(managerKey);
        v.update(cardPoint.value);
        if (!v.verify(Arrays.copyOfRange(seq.value, cardPoint.end, seq.value.length))) {
            throw new AssertionError("card ephemeral key signature invalid");
        }

        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(eph.getPrivate());
        ka.doPhase(publicKey(cardPoint.value, managerKey.getParams()), true);
        MessageDigest sha = MessageDigest.getInstance("SHA-384");
        sha.update(new byte[] {0, 0, 0, 1});
        sha.update(ka.generateSecret());
        sessionKey = Arrays.copyOf(sha.digest(), 32);
        return SW_OK;
    }

    /** PUT DATA 5F20 over SM; returns the SW (outer, or the protected one). */
    int putName(String name) throws GeneralSecurityException {
        return putData(0x5F20, name.getBytes(StandardCharsets.UTF_8));
    }

    /** PUT DATA DF02 over SM; returns the SW. */
    int putPlayerId(byte[] id) throws GeneralSecurityException {
        return putData(0xDF02, id);
    }

    int putData(int tag, byte[] data) throws GeneralSecurityException {
        byte[] r = storeData(SNAKE_AID, 0x01, nested(0xDA, tag >> 8, tag & 0xFF, wrap(0xDA, data, -1)));
        return sw(r) != SW_OK ? sw(r) : unwrap(r).sw;
    }

    // --- Leaderboard ---

    static final byte[] SCORE_CONTEXT = "armis-snake score".getBytes(StandardCharsets.US_ASCII);

    /** Response of SIGN SCORE (80 40): player id, high score and the card-key signature. */
    public static final class SignedScore {
        public final byte[] playerId;
        public final int score;
        public final byte[] signature;

        public SignedScore(byte[] response) {
            playerId = Arrays.copyOf(response, 16);
            score = ((response[16] & 0xFF) << 8) | (response[17] & 0xFF);
            signature = Arrays.copyOfRange(response, 18, response.length);
        }

        /** What the leaderboard checks: the card key signed this id, nonce and score. */
        public boolean verify(ECPublicKey cardKey, byte[] nonce) throws GeneralSecurityException {
            Signature v = Signature.getInstance("SHA384withECDSA");
            v.initVerify(cardKey);
            v.update(concat(SCORE_CONTEXT, playerId, nonce, new byte[] {(byte) (score >> 8), (byte) score}));
            return v.verify(signature);
        }
    }

    /** SIGN SCORE as a host would send it; returns data + SW. */
    public byte[] signScore(byte[] nonce) {
        return sim.transmitCommand(concat(new byte[] {(byte) 0x80, 0x40, 0, 0, (byte) nonce.length}, nonce, new byte[] {0}));
    }

    /** Signs the high score with a fresh nonce and checks it with the Manager key; returns the score. */
    public int verifiedScore() throws GeneralSecurityException {
        byte[] nonce = new byte[32];
        new java.security.SecureRandom().nextBytes(nonce);
        SignedScore s = new SignedScore(ok(signScore(nonce)));
        if (!s.verify(managerKey, nonce)) {
            throw new AssertionError("score signature invalid");
        }
        return s.score;
    }

    /** ISO 7816-4 SM as in SecureMessagingChannel: AES-CBC, zero IV, ISO 9797-1 M2 padding, zero MAC. */
    byte[] wrap(int ins, byte[] data, int le) throws GeneralSecurityException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (data.length > 0) {
            byte[] enc = aes(Cipher.ENCRYPT_MODE, pad(data));
            out.writeBytes((ins & 1) != 0 ? tlv(0x85, enc) : tlv(0x87, concat(new byte[] {1}, enc)));
        }
        if (le >= 0) {
            out.writeBytes(tlv(0x97, BigInteger.valueOf(le).toByteArray()));
        }
        out.writeBytes(tlv(0x8E, new byte[8]));
        return out.toByteArray();
    }

    static final class Unwrapped {
        byte[] data = new byte[0];
        int sw = -1;
    }

    Unwrapped unwrap(byte[] response) throws GeneralSecurityException {
        byte[] r = ok(response);
        Unwrapped u = new Unwrapped();
        for (int i = 0; i < r.length; ) {
            Tlv t = Tlv.parse(r, i);
            if (t.tag == 0x87) {
                u.data = unpad(aes(Cipher.DECRYPT_MODE, Arrays.copyOfRange(t.value, 1, t.value.length)));
            } else if (t.tag == 0x85) {
                u.data = unpad(aes(Cipher.DECRYPT_MODE, t.value));
            } else if (t.tag == 0x99) {
                u.sw = ((t.value[0] & 0xFF) << 8) | (t.value[1] & 0xFF);
            }
            i = t.end;
        }
        return u;
    }

    byte[] aes(int mode, byte[] data) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
        c.init(mode, new SecretKeySpec(sessionKey, "AES"), new IvParameterSpec(new byte[16]));
        return c.doFinal(data);
    }

    // --- Transport ---

    /** Plain APDU to the card; returns data + SW. */
    public byte[] apdu(String hex) {
        return sim.transmitCommand(hex(hex));
    }

    /** GP STORE DATA (80 E2) delivered to the applet's Personalization.processData(); returns data + SW. */
    public byte[] storeData(byte[] aid, int p1, byte[] data) {
        byte[] apdu = new byte[261];
        byte[] header = {(byte) 0x80, (byte) 0xE2, (byte) p1, (byte) sequence++, (byte) data.length};
        System.arraycopy(header, 0, apdu, 0, 5);
        System.arraycopy(data, 0, apdu, 5, data.length);
        try {
            short n = rt.storeData(aid, apdu, 5 + data.length);
            return concat(Arrays.copyOf(apdu, n), new byte[] {(byte) 0x90, 0});
        } catch (ISOException e) {
            short sw = e.getReason();
            return new byte[] {(byte) (sw >> 8), (byte) sw};
        }
    }

    public static int sw(byte[] r) {
        return ((r[r.length - 2] & 0xFF) << 8) | (r[r.length - 1] & 0xFF);
    }

    public static byte[] ok(byte[] r) {
        expect(SW_OK, sw(r), "SW");
        return Arrays.copyOf(r, r.length - 2);
    }

    public static void expect(Object want, Object got, String what) {
        if (!want.equals(got)) {
            String fmt = want instanceof Integer && (Integer) want > 0xFF ? "%04X" : "%s";
            throw new AssertionError(what + ": expected " + String.format(fmt, want) + ", got " + String.format(fmt, got));
        }
    }

    static byte[] nested(int ins, int p1, int p2, byte[] data) {
        return concat(new byte[] {(byte) ins, (byte) p1, (byte) p2, (byte) data.length}, data);
    }

    // --- Encoding helpers ---

    static final class Tlv {
        int tag, end;
        byte[] value;

        static Tlv parse(byte[] b, int i) {
            Tlv t = new Tlv();
            t.tag = b[i++] & 0xFF;
            int len = b[i++] & 0xFF;
            if (len > 0x80) {
                int n = len & 0x7F;
                len = 0;
                while (n-- > 0) {
                    len = (len << 8) | (b[i++] & 0xFF);
                }
            }
            t.value = Arrays.copyOfRange(b, i, i + len);
            t.end = i + len;
            return t;
        }
    }

    static byte[] tlv(int tag, byte[] value) {
        int n = value.length;
        byte[] len = n < 0x80 ? new byte[] {(byte) n}
                : n < 0x100 ? new byte[] {(byte) 0x81, (byte) n}
                : new byte[] {(byte) 0x82, (byte) (n >> 8), (byte) n};
        return concat(new byte[] {(byte) tag}, len, value);
    }

    static byte[] lv(byte[] value) {
        return concat(new byte[] {(byte) value.length}, value);
    }

    static byte[] pad(byte[] data) {
        byte[] p = Arrays.copyOf(data, (data.length / 16 + 1) * 16);
        p[data.length] = (byte) 0x80;
        return p;
    }

    static byte[] unpad(byte[] data) {
        int i = data.length - 1;
        while (data[i] == 0) {
            i--;
        }
        return Arrays.copyOf(data, i);
    }

    public static KeyPair generate() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec("secp384r1"));
            return g.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] issuerPoint(KeyPair key) {
        return point(((ECPublicKey) key.getPublic()).getW());
    }

    static ECPublicKey publicKey(byte[] point, ECParameterSpec curve) throws GeneralSecurityException {
        ECPoint w = new ECPoint(new BigInteger(1, Arrays.copyOfRange(point, 1, 1 + FIELD_LEN)),
                new BigInteger(1, Arrays.copyOfRange(point, 1 + FIELD_LEN, POINT_LEN)));
        return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(w, curve));
    }

    static byte[] point(ECPoint w) {
        return concat(new byte[] {4}, fixed(w.getAffineX()), fixed(w.getAffineY()));
    }

    static byte[] fixed(BigInteger v) {
        byte[] b = v.toByteArray();
        byte[] out = new byte[FIELD_LEN];
        int n = Math.min(b.length, FIELD_LEN);
        System.arraycopy(b, b.length - n, out, FIELD_LEN - n, n);
        return out;
    }

    static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            out.writeBytes(p);
        }
        return out.toByteArray();
    }

    static byte[] hex(String s) {
        s = s.replace(" ", "");
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return b;
    }
}
