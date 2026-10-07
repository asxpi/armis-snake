package cardsnake;

import ee.openeid.armis.applet.ecosystem.libs.AbstractApplet;
import ee.openeid.armis.applet.ecosystem.libs.TlvUtils;
import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

import static ee.openeid.armis.applet.ecosystem.libs.TlvUtils.SHORT_0;

/**
 * Snake as an ARMIS client applet for Estonian ID cards.
 *
 * The game is played over plain APDUs (docs/API.md) and the high score is
 * kept on the card. AbstractApplet handles the ARMIS install: registration
 * with the Manager applet and the issuer key. The issuer personalizes nothing,
 * so any further STORE DATA is refused.
 */
public class ArmisSnake extends AbstractApplet {
    private static final byte CLA = (byte) 0x80;

    private final SnakeGame game;

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
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buf = apdu.getBuffer();
        if (buf[ISO7816.OFFSET_CLA] != CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        apdu.setOutgoingAndSend(SHORT_0, game.process(buf[ISO7816.OFFSET_INS], buf[ISO7816.OFFSET_P1], buf));
    }

    /** STORE DATA after the install is finalized; the issuer sends none. */
    protected short processData(boolean isLastOrOnly, byte encryption, byte dataStructure, boolean isResponseExpected,
                                short sequence, byte[] inBuffer, short inOffset, short inLength,
                                byte[] outBuffer, short outOffset) {
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        return 0;
    }

    protected boolean isAuthenticated() {
        return false;
    }

    protected void flushAuthentication() {
    }
}
