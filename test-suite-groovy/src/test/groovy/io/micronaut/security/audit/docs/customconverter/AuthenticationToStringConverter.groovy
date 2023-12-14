package io.micronaut.security.audit.docs.customconverter

//tag::clazz[]
import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.core.convert.ConversionContext
import io.micronaut.core.convert.TypeConverter
import io.micronaut.security.audit.PrincipalToStringConverter
import io.micronaut.security.authentication.Authentication
import jakarta.inject.Singleton

//end::clazz[]
@Requires(property = "spec.name", value = "CustomPrincipalConverterSpec")
//tag::clazz[]
@Replaces(PrincipalToStringConverter.class) //1
@Singleton
class AuthenticationToStringConverter implements TypeConverter<Authentication, String> { //2
    @Override
    Optional<String> convert(Authentication authentication, Class<String> targetType, ConversionContext context) {
        Optional.ofNullable(authentication.attributes.get("CUSTOM_ID_ATTR")).map(Object::toString) //3
    }
}
//end::clazz[]
