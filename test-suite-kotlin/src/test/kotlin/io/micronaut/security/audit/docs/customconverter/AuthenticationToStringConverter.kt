package io.micronaut.security.audit.docs.customconverter

//tag::clazz[]
import io.micronaut.context.annotation.Requires
import io.micronaut.core.convert.ConversionContext
import io.micronaut.core.convert.TypeConverter
import io.micronaut.security.authentication.Authentication
import jakarta.inject.Singleton
import java.util.*

//end::clazz[]
@Requires(property = "spec.name", value = "CustomPrincipalConverterTest")
//tag::clazz[]
@Singleton
class AuthenticationToStringConverter : TypeConverter<Authentication, String> { // <1>
    override fun convert(
        authentication: Authentication,
        targetType: Class<String>,
        context: ConversionContext
    ): Optional<String> {
        return Optional.ofNullable(authentication.getAttributes()["CUSTOM_ID_ATTR"]).map { obj -> obj.toString() } // <3>
    }
}
//end::clazz[]
