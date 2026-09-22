# tag::exampleControllerPlusImports[]
from jakarta.annotation.security import PermitAll, RolesAllowed
from micronaut.http import MediaType
from micronaut.http.annotation import Controller, Get, Produces
# end::exampleControllerPlusImports[]
from micronaut.context.annotation import Requires


@Requires(property="spec.name", value="PermitAllTest")
# tag::exampleControllerPlusImports[]

@Controller("/example")
class ExampleController:

    @Produces(MediaType.TEXT_PLAIN)
    @Get("/admin")
    @RolesAllowed(["ROLE_ADMIN", "ROLE_X"])  # <1>
    def withroles(self) -> str:
        return "You have ROLE_ADMIN or ROLE_X roles"

    @Produces(MediaType.TEXT_PLAIN)
    @Get("/anonymous")
    @PermitAll  # <2>
    def anonymous(self) -> str:
        return "You are anonymous"
# end::exampleControllerPlusImports[]
