package cardsnake.issuer.model;

import lombok.NonNull;
import lombok.Value;

@Value
public class ContinueResponse {
    @NonNull
    StoreDataCommand storeDataCommand;
}
