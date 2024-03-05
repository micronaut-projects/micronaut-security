package example;

import io.micronaut.http.HttpResponse;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.UsernamePasswordCredentials;
import io.micronaut.security.ldap.LdapAuthenticationProvider;
import io.micronaut.security.rules.SecurityRule;
import jakarta.inject.Inject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Controller
@Secured(SecurityRule.IS_ANONYMOUS)
public class LdapController {

    private static final Logger LOG = LoggerFactory.getLogger("LdapController");

    @Inject
    LdapAuthenticationProvider authenticationProvider;

    @Post("/login")
    public MutableHttpResponse<Boolean> login(@Body UsernamePasswordCredentials usernamePasswordCredentials) {
        AuthenticationResponse authenticationResponse = authenticationProvider.authenticate(null, usernamePasswordCredentials);
        if (!authenticationResponse.isAuthenticated()) {
            LOG.error("Login failed");
        }
        return HttpResponse.ok(authenticationResponse.isAuthenticated());
    }
}
