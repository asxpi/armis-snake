package cardsnake.issuer.model;

import com.fasterxml.jackson.annotation.JsonEnumDefaultValue;

public enum PersonalizationRemovedEventType {
    UNINSTALLED_BY_USER,
    STORE_DATA_CHAIN_COMPLETED_BUT_ISSUER_TRIED_TO_CONTINUE,
    STORE_DATA_CHAIN_NOT_COMPLETED_BY_ISSUER,
    INVALID_RESPONSE_BY_ISSUER,
    REQUEST_TIMEOUT_BY_ISSUER,
    APPLET_INSTALL_ERROR,
    CARD_HOLDER_COMMUNICATION_ERROR,
    UNSPECIFIED_ERROR,
    @JsonEnumDefaultValue UNKNOWN
}
