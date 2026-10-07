package cardsnake.issuer;

import lombok.Getter;

public class IssuerAbortedPersonalizationException extends RuntimeException {

    @Getter
    private final Integer reasonCode;

    public IssuerAbortedPersonalizationException(Integer reasonCode) {
        super("Issuer responded that personalization failed or not allowed and reason code is " + reasonCode);
        this.reasonCode = reasonCode;
    }

}
