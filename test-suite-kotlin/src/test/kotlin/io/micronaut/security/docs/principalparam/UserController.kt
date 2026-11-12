package io.micronaut.security.docs.principalparam

//tag::imports[]
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.security.annotation.Secured
import java.security.Principal
//end::imports[]
import io.micronaut.context.annotation.Requires

@Requires(property = "spec.name", value = "PrincipalParamTest")
//tag::clazz[]

@Controller("/user")
class UserController {

    @Secured("isAnonymous()")
    @Get("/myinfo")
    fun myinfo(principal: Principal?): Map<String, Any> {
        if (principal == null) {
            return mapOf("isLoggedIn" to false)
        }
        return mapOf("isLoggedIn" to true, "username" to principal.name)
    }
}
//end::clazz[]
