package io.micronaut.security.docs.customauthentication

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.core.util.StringUtils
import io.micronaut.http.HttpRequest
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.token.validator.TokenValidator
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import org.reactivestreams.Publisher
import reactor.core.publisher.Mono
import spock.lang.Specification


@Property(name = "spec.name", value = "CustomAuthenticationTest")
@Property(name = "micronaut.security.reject-not-found", value = StringUtils.FALSE)
@MicronautTest
class CustomAuthenticationTest extends Specification {

    @Inject
    @Client("/")
    HttpClient httpClient;

    void "customAuthentication"() {
        given:
        BlockingHttpClient client = httpClient.toBlocking()

        when:
        HttpRequest<?> request = HttpRequest.GET("/custom-authentication")
                .accept(MediaType.TEXT_PLAIN)
                .bearerAuth("xxx")
        String email = client.retrieve(request)

        then:
        noExceptionThrown()
        "sherlock@micronaut.example" == email
    }

    @Requires(property = "spec.name", value = "CustomAuthenticationTest")
    @Controller
    static class CustomAuthenticationController {
//tag::method[]
        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Produces(MediaType.TEXT_PLAIN)
        @Get("/custom-authentication")
        String index(AuthenticationWithEmail authentication) {
            authentication.email
        }
//end::method[]
    }

    @Requires(property = "spec.name", value = "CustomAuthenticationTest")
    @Controller
    static class CustomAuthenticationProvider implements TokenValidator<HttpRequest<?>> {
        @Override
        Publisher<Authentication> validateToken(String token, HttpRequest<?> request) {
            Mono.just(Authentication.build("sherlock", [email: "sherlock@micronaut.example"]))
        }
    }
}
