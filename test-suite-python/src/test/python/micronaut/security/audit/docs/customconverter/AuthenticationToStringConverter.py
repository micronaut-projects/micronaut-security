# tag::clazz[]
from jakarta.inject import Singleton
from java.util import Optional
from micronaut.context.annotation import Requires
from micronaut.core.convert import ConversionContext, TypeConverter
from micronaut.security.authentication import Authentication

# end::clazz[]
@Requires(property="spec.name", value="CustomPrincipalConverterTest")
# tag::clazz[]
@Singleton
class AuthenticationToStringConverter(TypeConverter[Authentication, str]):  # <1>
    def convert(self, authentication: Authentication, targetType: type[str], context: ConversionContext) -> Optional[str]:
        return Optional.ofNullable(authentication.getAttributes().get("CUSTOM_ID_ATTR")).map(lambda value: str(value))  # <2>
# end::clazz[]
