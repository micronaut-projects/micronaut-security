# tag::imports[]
from micronaut.http.annotation import Controller, Get
from micronaut.security.annotation import Secured
from micronaut.security.authentication import Authentication
# end::imports[]
from micronaut.context.annotation import Requires


@Requires(property="spec.name", value="AuthenticationParamTest")
# tag::clazz[]

@Controller("/user")
class UserController:

    @Secured("isAnonymous()")
    @Get("/myinfo")
    def myinfo(self, authentication: Authentication | None) -> dict:
        if authentication is None:
            return {"isLoggedIn": False}
        return {"isLoggedIn": True,
                "username": authentication.getName(),
                "roles": list(authentication.getRoles())}
# end::clazz[]
