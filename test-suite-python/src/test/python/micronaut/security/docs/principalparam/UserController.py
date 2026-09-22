# tag::imports[]
from java.security import Principal
from micronaut.http.annotation import Controller, Get
from micronaut.security.annotation import Secured
# end::imports[]
from micronaut.context.annotation import Requires


@Requires(property="spec.name", value="PrincipalParamTest")
# tag::clazz[]

@Controller("/user")
class UserController:

    @Secured("isAnonymous()")
    @Get("/myinfo")
    def myinfo(self, principal: Principal | None) -> dict:
        if principal is None:
            return {"isLoggedIn": False}
        return {"isLoggedIn": True, "username": principal.getName()}
# end::clazz[]
