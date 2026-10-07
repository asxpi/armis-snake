import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/**
 * Rewrites a CAP file so that identical sources give identical bytes: fixed
 * entry timestamps, fixed manifest creation time, all entries stored, entry
 * order kept. The CAP components themselves are left untouched.
 *
 * Usage: NormalizeCap <in.cap> <out.cap>
 */
public class NormalizeCap {
    static final LocalDateTime EPOCH = LocalDateTime.of(1980, 1, 1, 0, 0);
    static final String CREATION_TIME = "Java-Card-CAP-Creation-Time: Tue Jan 01 00:00:00 UTC 1980";

    public static void main(String[] args) throws IOException {
        try (ZipFile in = new ZipFile(args[0]);
             ZipOutputStream out = new ZipOutputStream(new FileOutputStream(args[1]))) {
            for (ZipEntry e : Collections.list(in.entries())) {
                byte[] data = in.getInputStream(e).readAllBytes();
                if (e.getName().equals("META-INF/MANIFEST.MF")) {
                    data = new String(data, StandardCharsets.UTF_8)
                            .replaceAll("(?m)^Java-Card-CAP-Creation-Time: .*$", CREATION_TIME)
                            .getBytes(StandardCharsets.UTF_8);
                }
                CRC32 crc = new CRC32();
                crc.update(data);
                ZipEntry n = new ZipEntry(e.getName());
                n.setMethod(ZipEntry.STORED);
                n.setSize(data.length);
                n.setCrc(crc.getValue());
                n.setTimeLocal(EPOCH);
                out.putNextEntry(n);
                out.write(data);
                out.closeEntry();
            }
        }
    }
}
