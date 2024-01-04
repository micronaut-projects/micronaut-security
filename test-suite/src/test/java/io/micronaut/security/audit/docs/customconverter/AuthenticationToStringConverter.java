package io.micronaut.security.audit.docs.customconverter;

//tag::clazz[]
import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.convert.ConversionContext;
import io.micronaut.core.convert.TypeConverter;
import io.micronaut.security.converters.PrincipalToStringConverter;
import io.micronaut.security.authentication.Authentication;
import jakarta.inject.Singleton;

import java.util.Optional;

//end::clazz[]
@Requires(property = "spec.name", value = "CustomPrincipalConverterTest")
//tag::clazz[]
@Singleton
public class AuthenticationToStringConverter implements TypeConverter<Authentication, String> { // <1>
    @Override
    public Optional<String> convert(Authentication authentication, Class<String> targetType, ConversionContext context) {
        return Optional.ofNullable(authentication.getAttributes().get("CUSTOM_ID_ATTR")).map(Object::toString); // <2>
    }
}
//end::clazz[]
