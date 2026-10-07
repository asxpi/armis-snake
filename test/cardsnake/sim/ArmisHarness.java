package cardsnake.sim;

import cardsnake.ArmisSnake;
import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.base.SimulatorRuntime;
import com.licel.jcardsim.utils.AIDUtil;
import ee.openeid.armis.applet.ecosystem.ManagerApplet;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import javacard.framework.ISOException;
import org.globalplatform.Personalization;

/**
 * Plays ARMIS against jCardSim, following armis-cli: personalizes the Manager
 * applet, installs ArmisSnake and finalizes the install with the issuer key.
 *
 * Differences from a real card: STORE DATA calls processData() directly
 * instead of going through a GlobalPlatform security domain, the Manager
 * certificate is a DER stand-in holding its public key instead of an ARMIS
 * CA X.509 certificate, and jCardSim's key generation is deterministic, so
 * every simulated card has the same card key.
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
    int sequence;

    public ArmisHarness() {
        this(generate());
    }

    /** issuer: the issuer key pair; only its public half goes to the card. */
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
