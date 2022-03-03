package io.micronaut.docs.security.principalparam

import io.micronaut.context.annotation.Requires;

//tag::imports[]

import io.micronaut.core.annotation.Nullable
import io.micronaut.core.util.CollectionUtils
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.security.annotation.Secured

import java.security.Principal

//end::imports[]

// Although this is a Groovy file this is written as close to Java as possible to embedded in the docs

@Requires(property = 'spec.name', value = 'principalparam')
//tag::clazz[]
@Controller("/user")
public class UserController {

    @Secured("isAnonymous()")
    @Get("/myinfo")
    public Map myinfo(@Nullable Principal principal) {
        if (principal == null) {
            return Collections.singletonMap("isLoggedIn", false);
        }
        return CollectionUtils.mapOf("isLoggedIn", true, "username", principal.getName());
    }
}
//end::clazz[]
