package cardsnake.issuer;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.HexFormat;
import java.util.Locale;

/**
 * A player registered at install. Only what score checks need is kept: the
 * card holder certificate itself, with the personal code, is not.
 *
 * @param id          random id the issuer puts on the card; the card signs it with every score
 * @param name        given name from the certificate, fitted to the applet's 16-byte limit
 * @param cardKey     the card's ARMIS key from the certificate, which verifies signed scores
 * @param certificate SHA-256 of the certificate, to find the player when ARMIS reports removal
 */
public record Player(String id, String name, ECPublicKey cardKey, String certificate) {

    static final int ID_LENGTH = 16;
    static final int NAME_MAX = 16;
    static final String DEFAULT_NAME = "Player";

    public static Player of(X509Certificate certificate, SecureRandom random) {
        byte[] id = new byte[ID_LENGTH];
        random.nextBytes(id);
        X500Name subject = X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded());
        RDN[] givenName = subject.getRDNs(BCStyle.GIVENNAME);
        String name = givenName.length == 0 ? DEFAULT_NAME : titleCase(IETFUtils.valueToString(givenName[0].getFirst().getValue()));
        return new Player(HexFormat.of().formatHex(id), fit(name), (ECPublicKey) certificate.getPublicKey(), fingerprint(certificate));
    }

    public byte[] idBytes() {
        return HexFormat.of().parseHex(id);
    }

    static String fingerprint(X509Certificate certificate) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            throw new IllegalArgumentException("Bad card holder certificate", e);
        }
    }

    /** "MARI-LIIS" -> "Mari-Liis": ID cards store names in capitals. */
    static String titleCase(String s) {
        StringBuilder out = new StringBuilder(s.length());
        boolean start = true;
        for (char c : s.toLowerCase(Locale.ROOT).toCharArray()) {
            out.append(start ? Character.toUpperCase(c) : c);
            start = c == ' ' || c == '-';
        }
        return out.toString();
    }

    /** Trims to NAME_MAX UTF-8 bytes without splitting a character. */
    static String fit(String s) {
        int bytes = 0;
        int end = 0;
        while (end < s.length()) {
            int cp = s.codePointAt(end);
            int len = new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8).length;
            if (bytes + len > NAME_MAX) {
                break;
            }
            bytes += len;
            end += Character.charCount(cp);
        }
        return s.substring(0, end);
    }
}
