from java.security import Principal
from micronaut.context.annotation import Requires
from micronaut.http import MediaType
from micronaut.http.annotation import Controller, Get, Produces
from micronaut.security.annotation import Secured


@Requires(property="spec.name", value="docexpressions")
# tag::exampleControllerExpressions[]
@Controller("/authenticated")
class ExampleController:

    @Secured("#{ user?.attributes?.get('email') == 'sherlock@micronaut.example' }")
    @Produces(MediaType.TEXT_PLAIN)
    @Get("/email")
    def authentication_by_email(self, principal: Principal) -> str:
        return principal.getName() + " is authenticated"
# end::exampleControllerExpressions[]
