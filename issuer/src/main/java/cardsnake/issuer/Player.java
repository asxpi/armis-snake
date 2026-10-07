package cardsnake.issuer;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import java.util.Locale;

/**
 * A player as identified by the ARMIS card holder certificate.
 *
 * @param id   SHA-256 of the certificate subject serial number (personal code), so the
 *             service never keeps the personal code itself
 * @param name given name from the certificate, fitted to the applet's 16-byte limit
 */
public record Player(String id, String name) {

    static final int NAME_MAX = 16;
    static final String DEFAULT_NAME = "Player";

    public static Player of(X509Certificate certificate) {
        X500Name subject = X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded());
        String serial = attribute(subject, BCStyle.SERIALNUMBER);
        byte[] idSource;
        try {
            idSource = serial != null ? serial.getBytes(StandardCharsets.UTF_8) : certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new IllegalArgumentException("Bad card holder certificate", e);
        }
        String givenName = attribute(subject, BCStyle.GIVENNAME);
        return new Player(sha256(idSource), fit(givenName != null ? titleCase(givenName) : DEFAULT_NAME));
    }

    private static String attribute(X500Name subject, ASN1ObjectIdentifier type) {
        RDN[] rdns = subject.getRDNs(type);
        return rdns.length == 0 ? null : IETFUtils.valueToString(rdns[0].getFirst().getValue());
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

    private static String sha256(byte[] data) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
