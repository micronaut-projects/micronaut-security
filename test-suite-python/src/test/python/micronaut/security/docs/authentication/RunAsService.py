from jakarta.inject import Singleton
from micronaut.context.annotation import Requires
from micronaut.security.annotation import RunAs
from micronaut.security.authentication import Authentication
from micronaut.security.context import SecurityContextHolder


@Requires(property="spec.name", value="RunAsTest")
# tag::clazz[]
@RunAs(
    name="aegon",
    roles=["TARGARYEN"],
    attributes=[
        RunAs.Attribute(key="family_name", value="Targaryen"),
        RunAs.Attribute(key="given_name", value="Aegon"),
    ],
)
@Singleton
class RunAsService:
    def change_auth(self) -> Authentication:
        return SecurityContextHolder.getSecurityContext().getAuthentication()
# end::clazz[]
