package io.micronaut.docs.security.securityRule.secured;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;

import javax.annotation.security.RolesAllowed;
import java.util.HashMap;
import java.util.Map;

@Controller("/multiple")
@Requires(property = "spec.name", value = "MultipleAnnotationsControllerSpec")
public class MultipleAnnotationsController {

    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Get("/index")
    @RolesAllowed("ROLE_USER")
    public Map<String, Object> index() {
        Map<String, Object> model = new HashMap<>();
        model.put("books", "some books");
        return model;
    }

}
