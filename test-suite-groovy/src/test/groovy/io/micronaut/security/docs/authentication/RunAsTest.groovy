package io.micronaut.security.docs.authentication

import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.core.type.Argument
import io.micronaut.http.HttpRequest
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.ClientAuthentication
import io.micronaut.security.authentication.provider.HttpRequestAuthenticationProvider
import io.micronaut.security.context.SecurityContextHolder
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import jakarta.inject.Singleton
import spock.lang.Specification

@Property(name = "spec.name", value = "RunAsTest")
@MicronautTest
class RunAsTest extends Specification {

    @Inject
    @Client("/")
    HttpClient httpClient

    void "verify you can use the RunAs annotation to change the SecurityContextHolder for the scope of a class"() {
        given:
        BlockingHttpClient client = httpClient.toBlocking()

        when:
        List<ClientAuthentication> authentications = client.retrieve(
                HttpRequest.GET("/runAs").basicAuth("john", "ilikedaenerys"),
                Argument.listOf(ClientAuthentication)
        )

        then:
        Authentication runAsExpected = Authentication.build(
                "aegon",
                ["ROLE_STARK", "TARGARYEN"],
                [family_name: "Targaryen", given_name: "Aegon", roles: ["ROLE_STARK", "TARGARYEN"]]
        )
        ClientAuthentication runAs = authentications[0]
        runAsExpected.name == runAs.name
        runAsExpected.roles.toList() == runAs.roles.toList()
        runAsExpected.attributes == runAs.attributes

        and:
        Authentication expected = Authentication.build(
                "john",
                ["ROLE_STARK"],
                [family_name: "Snow", given_name: "John", roles: ["ROLE_STARK"]]
        )
        ClientAuthentication authentication = authentications[1]
        expected.name == authentication.name
        expected.roles.toList() == authentication.roles.toList()
        expected.attributes == authentication.attributes
    }

    @Requires(property = "spec.name", value = "RunAsTest")
    @Singleton
    static class RunAsProvider<B> implements HttpRequestAuthenticationProvider<B> {
        @Override
        AuthenticationResponse authenticate(HttpRequest<B> requestContext,
                                            AuthenticationRequest<String, String> authRequest) {
            AuthenticationResponse.success(
                    "john",
                    ["ROLE_STARK"],
                    [family_name: "Snow", given_name: "John"]
            )
        }
    }

    @Requires(property = "spec.name", value = "RunAsTest")
    @Controller("/runAs")
    static class RunAsController {
        private final RunAsService runAuthService
        private final AuthService authService

        RunAsController(RunAsService runAuthService,
                        AuthService authService) {
            this.runAuthService = runAuthService
            this.authService = authService
        }

        @Secured("ROLE_STARK")
        @Get
        List<Authentication> index(Authentication authentication) {
            [runAuthService.changeAuth(), authService.auth()]
        }
    }

    @Requires(property = "spec.name", value = "RunAsTest")
    @Singleton
    static class AuthService {
        Authentication auth() {
            SecurityContextHolder.securityContext.authentication
        }
    }
}
