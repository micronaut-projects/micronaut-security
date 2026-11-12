# tag::exampleControllerPlusImports[]
from micronaut.http import MediaType
from micronaut.http.annotation import Controller, Get, Produces
from micronaut.security.annotation import Secured
from micronaut.security.authentication import Authentication
from micronaut.security.rules import SecurityRule
# end::exampleControllerPlusImports[]
from micronaut.context.annotation import Requires


@Requires(property="spec.name", value="SecuredTest")
# tag::exampleControllerPlusImports[]

@Controller("/example")
@Secured(SecurityRule.IS_AUTHENTICATED)  # <1>
class ExampleController:

    @Produces(MediaType.TEXT_PLAIN)
    @Get("/admin")
    @Secured(["ROLE_ADMIN", "ROLE_X"])  # <2>
    def withroles(self) -> str:
        return "You have ROLE_ADMIN or ROLE_X roles"

    @Produces(MediaType.TEXT_PLAIN)
    @Get("/anonymous")
    @Secured(SecurityRule.IS_ANONYMOUS)  # <3>
    def anonymous(self) -> str:
        return "You are anonymous"

    @Produces(MediaType.TEXT_PLAIN)
    @Get("/authenticated")  # <1>
    def authenticated(self, authentication: Authentication) -> str:
        return authentication.getName() + " is authenticated"
# end::exampleControllerPlusImports[]
