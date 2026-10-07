package cardsnake.issuer;

import com.payneteasy.tlv.BerTag;

public interface CommonAppletConstants {

    BerTag TAG_UNIVERSAL_INTEGER = new BerTag(0x02);
    BerTag TAG_UNIVERSAL_OCTET_STRING = new BerTag(0x04);
    BerTag TAG_UNIVERSAL_SEQUENCE = new BerTag(0x30);

}
