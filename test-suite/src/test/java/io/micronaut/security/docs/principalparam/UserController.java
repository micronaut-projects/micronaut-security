package io.micronaut.security.docs.principalparam;

//tag::imports[]
import io.micronaut.core.util.CollectionUtils;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.security.annotation.Secured;
import org.jspecify.annotations.Nullable;

import java.security.Principal;
import java.util.Collections;
import java.util.Map;
//end::imports[]
import io.micronaut.context.annotation.Requires;

@Requires(property = "spec.name", value = "PrincipalParamTest")
//tag::clazz[]

@Controller("/user")
public class UserController {

    @Secured("isAnonymous()")
    @Get("/myinfo")
    public Map<String, Object> myinfo(@Nullable Principal principal) {
        if (principal == null) {
            return Collections.singletonMap("isLoggedIn", false);
        }
        return CollectionUtils.mapOf("isLoggedIn", true, "username", principal.getName());
    }
}
//end::clazz[]
