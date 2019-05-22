package mock;

import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;

import java.security.Principal;

@Secured(SecurityRule.IS_AUTHENTICATED)
@Controller
public class HomeController {

    @Get(produces = MediaType.TEXT_HTML)
    String index(Principal principal) {
        return """
<html>
    <head>
        <title>Home</title>
    </head>
    <body>
        Hello ${principal.getName()}
    </body>
</html>
"""
    }
}
