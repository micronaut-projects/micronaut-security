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
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

@Controller
@Secured(SecurityRule.IS_ANONYMOUS)
public class LdapController {

    private static final Logger logger = LoggerFactory.getLogger("LdapController");

    @Inject
    LdapAuthenticationProvider authenticationProvider;

    @Post("/login")
    public Mono<MutableHttpResponse<Boolean>> login(@Body UsernamePasswordCredentials usernamePasswordCredentials) {
        Publisher<AuthenticationResponse> publisher = authenticationProvider.authenticate(null, usernamePasswordCredentials);
        return Mono.fromDirect(publisher).map(r -> HttpResponse.ok(r.isAuthenticated())).onErrorResume(e -> {
            logger.error("Login failed", e);
            return Mono.just(HttpResponse.ok(false));
        });
    }
}
