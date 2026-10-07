package cardsnake.issuer.helpers.json;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.google.protobuf.ByteString;
import org.springframework.boot.jackson.JsonComponent;

import java.io.IOException;

@JsonComponent
public class ByteStringSerializer extends StdSerializer<ByteString> {

    public ByteStringSerializer() {
        super(ByteString.class);
    }

    @Override
    public void serialize(ByteString bytes, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
        jsonGenerator.writeBinary(bytes.toByteArray());
    }

}
