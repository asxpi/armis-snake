package cardsnake;

import ee.openeid.armis.applet.ecosystem.libs.AbstractApplet;
import ee.openeid.armis.applet.ecosystem.libs.ECDHE;
import ee.openeid.armis.applet.ecosystem.libs.ShareableSignature;
import ee.openeid.armis.applet.ecosystem.libs.TlvUtils;
import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

import static ee.openeid.armis.applet.ecosystem.libs.TlvUtils.SHORT_0;
import static ee.openeid.armis.applet.ecosystem.libs.TlvUtils.SIZE_OF_BYTE;

/**
 * Snake as an ARMIS client applet for Estonian ID cards.
 *
 * The game is played over plain APDUs (docs/API.md). At install, the issuer
 * (a leaderboard service) personalizes the applet through ARMIS STORE DATA:
 * it authenticates with INTERNAL AUTHENTICATE (ECDHE against the Manager
 * applet's card key), then sets the player name and a player id over secure
 * messaging. Afterwards the applet signs its high score, the player id and a
 * leaderboard nonce with the card key, so any host can relay the score and
 * the leaderboard can check that it was played on that card.
 */
public class ArmisSnake extends AbstractApplet {
    private static final byte CLA = (byte) 0x80;
    private static final byte INS_GET_NAME = (byte) 0x30;
    private static final byte INS_SIGN_SCORE = (byte) 0x40;

    private static final short TAG_PLAYER_NAME = (short) 0x5F20;  // ISO 7816-6 cardholder name
    private static final short TAG_PLAYER_ID = (short) 0xDF02;
    private static final short NAME_MAX = 16;
    private static final short PLAYER_ID_LENGTH = 16;
    private static final short NONCE_LENGTH = 32;

    // Prefix of every message this applet signs with the card key, so the
    // card key never signs host-chosen data that could mean something else
    private static final byte[] SCORE_CONTEXT = {
        'a', 'r', 'm', 'i', 's', '-', 's', 'n', 'a', 'k', 'e', ' ', 's', 'c', 'o', 'r', 'e'
    };

    private static final byte[] KDF_COUNTER = {0, 0, 0, 1};

    private final SnakeGame game;
    private final byte[] playerName;
    private short playerNameLength;
    private final byte[] playerId;
    private boolean playerIdSet;

    // Issuer session. CLEAR_ON_RESET, not DESELECT: personalization arrives
    // through the security domain while this applet is not selected.
    private final AESKey sessionKey;
    private final boolean[] authenticated;
    private final Cipher smCipher;
    private final Signature ecdsa;

    private static class Factory implements AppletFactory {
        public AbstractApplet create(byte[] bArray, short bOffset, short bLength, byte appletPrivileges, byte[] globalParserMetadata) {
            return new ArmisSnake(bArray, globalParserMetadata);
        }
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        install(new Factory(), bArray, bOffset, bLength);
    }

    private ArmisSnake(byte[] bArray, byte[] globalParserMetadata) {
        super(bArray, globalParserMetadata);
        if (TlvUtils.getParseLength(globalParserMetadata, SHORT_0) != 0) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        game = new SnakeGame();
        playerName = new byte[NAME_MAX];
        playerId = new byte[PLAYER_ID_LENGTH];
        sessionKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_256, false);
        authenticated = JCSystem.makeTransientBooleanArray((short) 1, JCSystem.CLEAR_ON_RESET);
        smCipher = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M2, false);
        ecdsa = Signature.getInstance(Signature.ALG_ECDSA_SHA_384, false);
    }

    /** Selecting the game ends any issuer session; the issuer must authenticate again. */
    public boolean select() {
        flushAuthentication();
        return true;
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buf = apdu.getBuffer();
        if (buf[ISO7816.OFFSET_CLA] != CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        byte ins = buf[ISO7816.OFFSET_INS];
        if (ins == INS_GET_NAME || ins == INS_SIGN_SCORE) {
            // ARMIS rule: nothing identifying over contactless without mutual authentication
            if ((byte) (APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK) != APDU.PROTOCOL_MEDIA_DEFAULT) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
        }
        if (ins == INS_GET_NAME) {
            Util.arrayCopyNonAtomic(playerName, SHORT_0, buf, SHORT_0, playerNameLength);
            apdu.setOutgoingAndSend(SHORT_0, playerNameLength);
        } else if (ins == INS_SIGN_SCORE) {
            apdu.setOutgoingAndSend(SHORT_0, signScore(apdu, buf));
        } else {
            apdu.setOutgoingAndSend(SHORT_0, game.process(ins, buf[ISO7816.OFFSET_P1], buf));
        }
    }

    /**
     * Signs SCORE_CONTEXT || player id || nonce || high score with the card key
     * through the Manager applet. Response: player id || high score || ECDSA-SHA384
     * signature (DER).
     */
    private short signScore(APDU apdu, byte[] buf) {
        if (!playerIdSet) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (apdu.setIncomingAndReceive() != NONCE_LENGTH || buf[ISO7816.OFFSET_LC] != NONCE_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short hiScore = game.getHiScore();

        // Buffers handed to the Manager cross the firewall, so they are global arrays
        short messageLength = (short) (SCORE_CONTEXT.length + PLAYER_ID_LENGTH + NONCE_LENGTH + 2);
        byte[] message = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, messageLength);
        short offset = Util.arrayCopyNonAtomic(SCORE_CONTEXT, SHORT_0, message, SHORT_0, (short) SCORE_CONTEXT.length);
        offset = Util.arrayCopyNonAtomic(playerId, SHORT_0, message, offset, PLAYER_ID_LENGTH);
        offset = Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, message, offset, NONCE_LENGTH);
        Util.setShort(message, offset, hiScore);

        ShareableSignature signer = getEcPrivateKeyService().forSigning(Signature.ALG_ECDSA_SHA_384);
        byte[] signature = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, signer.getLength());
        short signatureLength = signer.sign(message, SHORT_0, messageLength, signature, SHORT_0);
        signer.dispose();

        offset = Util.arrayCopyNonAtomic(playerId, SHORT_0, buf, SHORT_0, PLAYER_ID_LENGTH);
        offset = Util.setShort(buf, offset, hiScore);
        return Util.arrayCopyNonAtomic(signature, SHORT_0, buf, offset, signatureLength);
    }

    /** STORE DATA from the issuer, relayed by ARMIS through the security domain. */
    protected short processData(boolean isLastOrOnly, byte encryption, byte dataStructure, boolean isResponseExpected,
                                short sequence, byte[] inBuffer, short inOffset, short inLength,
                                byte[] outBuffer, short outOffset) {
        byte[] meta = TlvUtils.getNewGlobalMetadata();
        TlvUtils.setParserMetadata(inOffset, inLength, meta, SHORT_0);
        // Skip the STORE DATA header to the nested command
        TlvUtils.ensureParsableInputAvailable(ISO7816.OFFSET_CDATA, meta, SHORT_0);
        short nestedLength = TlvUtils.getParseLength(meta, SHORT_0);
        short insOffset = TlvUtils.ensureParsableInputAvailable(SIZE_OF_BYTE, meta, SHORT_0);
        byte ins = inBuffer[insOffset];

        if (ins == INS_INTERNAL_AUTHENTICATE) {
            return internalAuthenticate(inBuffer, (short) (inOffset + ISO7816.OFFSET_CDATA + OFFSET_NESTED_CDATA),
                    (short) (inLength - ISO7816.OFFSET_CDATA - OFFSET_NESTED_CDATA), outBuffer, outOffset);
        }

        // Everything else is under secure messaging. unwrap() decrypts in place
        // and appends the protected Le, so the remaining parse length grows by one.
        short plainLength = unwrap(true, smCipher, sessionKey, null, null, inBuffer, insOffset, nestedLength);
        TlvUtils.setParseLength((short) (TlvUtils.getParseLength(meta, SHORT_0)
                - (short) (nestedLength - plainLength - OFFSET_NESTED_P1)), meta, SHORT_0);

        short tag = TlvUtils.parseTlvTag2(inBuffer, meta, SHORT_0);
        if (ins != INS_PUT_DATA || (tag != TAG_PLAYER_NAME && tag != TAG_PLAYER_ID)) {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
        short length = TlvUtils.parseTlvInteger(SIZE_OF_BYTE, inBuffer, meta, SHORT_0);
        if (tag == TAG_PLAYER_NAME ? length > NAME_MAX : length != PLAYER_ID_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short dataOffset = TlvUtils.ensureParsableInputAvailable(length, meta, SHORT_0);
        JCSystem.beginTransaction();
        if (tag == TAG_PLAYER_NAME) {
            Util.arrayCopy(inBuffer, dataOffset, playerName, SHORT_0, length);
            playerNameLength = length;
        } else {
            Util.arrayCopy(inBuffer, dataOffset, playerId, SHORT_0, length);
            playerIdSet = true;
        }
        JCSystem.commitTransaction();
        return wrap(true, smCipher, sessionKey, null, null, ins, outBuffer, outOffset, (short) 0, ISO7816.SW_NO_ERROR);
    }

    /**
     * Verifies the issuer's signed ephemeral key, runs ECDHE through the
     * Manager applet and derives the AES session key. Returns the card's
     * ephemeral key signed with the Manager's card key.
     */
    private short internalAuthenticate(byte[] in, short off, short len, byte[] out, short outOff) {
        flushAuthentication();
        byte[] meta = TlvUtils.getNewGlobalMetadata();
        TlvUtils.setParserMetadata(off, len, meta, SHORT_0);
        // SEQUENCE { ecPubPoint OCTET STRING, ecdsaSignature SEQUENCE { r INTEGER, s INTEGER } }
        short seqLength = TlvUtils.ensureTlvTag1AndParseLength((byte) 0x30, in, meta, SHORT_0);
        short seqOffset = TlvUtils.getParseOffset(meta, SHORT_0);
        short keyLength = TlvUtils.ensureTlvTag1AndParseLength((byte) 0x04, in, meta, SHORT_0);
        short keyOffset = TlvUtils.ensureParsableInputAvailable(keyLength, meta, SHORT_0);
        short sigLength = (short) (seqLength - (short) (TlvUtils.getParseOffset(meta, SHORT_0) - seqOffset));
        short sigOffset = TlvUtils.ensureTlvTag1((byte) 0x30, in, meta, SHORT_0);

        ecdsa.init(issuerPublicKey, Signature.MODE_VERIFY);
        if (!ecdsa.verify(in, keyOffset, keyLength, in, sigOffset, sigLength)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        ECDHE ecdhe = getEcPrivateKeyService().performEcdhe(in, off, len);
        // The secret crosses the firewall from the Manager, so it arrives in a
        // temporary global array, followed by room for the derived key.
        short secretLength = ecdhe.getSecret(null, SHORT_0);
        short workLength = (short) (secretLength + MessageDigest.LENGTH_SHA_384);
        byte[] work = (byte[]) JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, workLength);
        ecdhe.getSecret(work, SHORT_0);

        // ConcatKDF(SHA-384) with no other info; one block covers the 32-byte key:
        // SHA-384(00000001 || secret). Done here rather than with the library's
        // ConcatKDF, which keeps its input array in a field, and references to
        // temporary global arrays must not be stored.
        digestSha384.reset();
        digestSha384.update(KDF_COUNTER, SHORT_0, (short) KDF_COUNTER.length);
        digestSha384.doFinal(work, SHORT_0, secretLength, work, secretLength);
        sessionKey.setKey(work, secretLength);
        Util.arrayFillNonAtomic(work, SHORT_0, workLength, (byte) 0);
        short length = ecdhe.getSignedEphemeralPublicKey(out, outOff);
        authenticated[0] = true;
        return length;
    }

    protected boolean isAuthenticated() {
        return authenticated[0];
    }

    protected void flushAuthentication() {
        authenticated[0] = false;
        sessionKey.clearKey();
    }
}
