package io.micronaut.security.docs.principalparam

//tag::imports[]
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.security.annotation.Secured
import org.jspecify.annotations.Nullable

import java.security.Principal
//end::imports[]
import io.micronaut.context.annotation.Requires

@Requires(property = "spec.name", value = "PrincipalParamTest")
//tag::clazz[]

@Controller("/user")
class UserController {

    @Secured("isAnonymous()")
    @Get("/myinfo")
    Map<String, Object> myinfo(@Nullable Principal principal) {
        if (principal == null) {
            return [isLoggedIn: false]
        }
        [isLoggedIn: true, username: principal.name]
    }
}
//end::clazz[]
