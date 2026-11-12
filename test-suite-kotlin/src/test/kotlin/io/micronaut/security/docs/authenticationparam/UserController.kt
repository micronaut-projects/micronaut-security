package io.micronaut.security.docs.authenticationparam

//tag::imports[]
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
//end::imports[]
import io.micronaut.context.annotation.Requires

@Requires(property = "spec.name", value = "AuthenticationParamTest")
//tag::clazz[]

@Controller("/user")
class UserController {

    @Secured("isAnonymous()")
    @Get("/myinfo")
    fun myinfo(authentication: Authentication?): Map<String, Any> {
        if (authentication == null) {
            return mapOf("isLoggedIn" to false)
        }
        return mapOf("isLoggedIn" to true,
                "username" to authentication.name,
                "roles" to authentication.roles
        )
    }
}
//end::clazz[]
