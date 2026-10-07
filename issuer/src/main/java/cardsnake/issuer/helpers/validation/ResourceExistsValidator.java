package cardsnake.issuer.helpers.validation;

import org.springframework.core.io.Resource;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class ResourceExistsValidator implements ConstraintValidator<ResourceExists, Resource> {

    @Override
    public boolean isValid(Resource resource, ConstraintValidatorContext constraintContext) {
        if (resource == null) return true;
        return resource.exists();
    }

}
