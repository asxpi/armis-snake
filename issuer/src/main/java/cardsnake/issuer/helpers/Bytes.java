package cardsnake.issuer.helpers;

import lombok.experimental.UtilityClass;

@UtilityClass
public final class Bytes {

    public static byte[] asArray(byte... values) {
        return values;
    }

    public static byte[] asArrayOfLength(int length, byte... values) {
        byte[] array = new byte[length];
        System.arraycopy(values, 0, array, 0, values.length);
        return array;
    }

    public static int copyIntoArray(byte[] array, int offset, byte... values) {
        System.arraycopy(values, 0, array, offset, values.length);
        return values.length;
    }

}
