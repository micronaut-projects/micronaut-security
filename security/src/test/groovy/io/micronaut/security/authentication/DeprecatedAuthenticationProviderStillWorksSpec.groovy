package io.micronaut.security.authentication

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.Nullable
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import reactor.core.publisher.Flux
import reactor.core.publisher.FluxSink
import spock.lang.Specification

import java.security.Principal

import static io.micronaut.http.HttpStatus.OK
import static io.micronaut.http.HttpStatus.UNAUTHORIZED
import static io.micronaut.http.MediaType.TEXT_PLAIN

@Property(name = "spec.name", value = "DeprecatedAuthenticationProviderStillWorksSpec")
@MicronautTest
class DeprecatedAuthenticationProviderStillWorksSpec extends Specification {

    @Inject
    @Client("/")
    HttpClient httpClient;

    void verifyHttpBasicAuthWorks() {
        given:
        BlockingHttpClient client = httpClient.toBlocking();

        when: 'Accessing a secured URL without authenticating'
        client.exchange(HttpRequest.GET("/").accept(TEXT_PLAIN));

        then: 'returns unauthorized'
        HttpClientResponseException thrown = thrown()
        UNAUTHORIZED == thrown.status

        when: 'A secured URL is accessed with Basic Auth'
        HttpResponse<String> rsp = client.exchange(HttpRequest.GET("/")
                        .accept(TEXT_PLAIN)
                        .basicAuth("sherlock", "password"),
                String)
        then: 'the endpoint can be accessed'
        noExceptionThrown()
        OK == rsp.status
        "sherlock" == rsp.body.get()
    }

    @Requires(property = "spec.name", value = "DeprecatedAuthenticationProviderStillWorksSpec")
    @Singleton
    static class AuthenticationProviderUserPassword implements AuthenticationProvider<HttpRequest<?>> {

        @Override
        Publisher<AuthenticationResponse> authenticate(@Nullable HttpRequest<?> httpRequest,
                                                              AuthenticationRequest<?, ?> authenticationRequest) {
            return Flux.create(emitter -> {
                if (authenticationRequest.getIdentity().equals("sherlock") &&
                        authenticationRequest.getSecret().equals("password")) {
                    emitter.next(AuthenticationResponse.success((String) authenticationRequest.getIdentity()));
                    emitter.complete()
                } else {
                    emitter.error(AuthenticationResponse.exception())
                }
            }, FluxSink.OverflowStrategy.ERROR)
        }
    }

    @Requires(property = "spec.name", value = "DeprecatedAuthenticationProviderStillWorksSpec")
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Controller
    static class HomeController {
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String index(Principal principal) {  // <4>
            return principal.getName();
        }
    }
}


