package cardsnake.issuer.helpers.json;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.google.protobuf.ByteString;
import org.springframework.boot.jackson.JsonComponent;

import java.io.IOException;

@JsonComponent
public class ByteStringDeserializer extends StdDeserializer<ByteString> {

    public ByteStringDeserializer() {
        super(ByteString.class);
    }

    @Override
    public ByteString deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException {
        return ByteString.copyFrom(jsonParser.getBinaryValue());
    }

}
