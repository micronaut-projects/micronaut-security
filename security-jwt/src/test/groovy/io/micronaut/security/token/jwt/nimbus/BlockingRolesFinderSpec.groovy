package io.micronaut.security.token.jwt.nimbus;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires
import io.micronaut.core.type.Argument
import io.micronaut.core.util.CollectionUtils
import io.micronaut.core.util.StringUtils
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario;
import io.micronaut.security.token.DefaultRolesFinder;
import io.micronaut.security.token.RolesFinder;
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import reactor.core.publisher.Mono;
import spock.lang.Specification

import java.security.Principal;
import java.util.List;
import java.util.Map;

@Property(name = "micronaut.security.token.jwt.signatures.secret.generator.secret", value = "pleaseChangeThisSecretForANewOne")
@Property(name = "micronaut.security.authentication", value = "bearer")
@Property(name = "micronaut.security.token.jwt.nimbus.reactive-validator-execute-on-blocking", value = StringUtils.TRUE)
@Property(name = "spec.name", value = "BlockingRolesFinderSpec")
@MicronautTest
class BlockingRolesFinderSpec extends Specification {

    @Inject
    @Client("/")
    HttpClient httpClient

    void "it is possible to subscribeOn if you have a blocking RolesFinder"() {
        given:
        BlockingHttpClient client = httpClient.toBlocking()

        when:
        HttpResponse<Map> response = client.exchange(loginRequest(), Map)

        then:
        noExceptionThrown()
        response.getBody().isPresent()
        response.getBody().get().containsKey("access_token")

        when:
        HttpRequest<?> request = HttpRequest.GET("/echo")
                .bearerAuth(response.body.get().get("access_token") as CharSequence)
        String json = client.retrieve(request)

        then:
        noExceptionThrown()
        '{"username":"john"}' == json
    }

    private static HttpRequest<?> loginRequest() {
        return HttpRequest.POST("/login",
                CollectionUtils.mapOf("username", "john", "password", "bogus"))
    }

    @Requires(property = "spec.name", value = "BlockingRolesFinderSpec")
    @Singleton
    static class CustomAuthenticationProvider extends MockAuthenticationProvider {
        CustomAuthenticationProvider() {
            super(Collections.singletonList(new SuccessAuthenticationScenario("john")))
        }
    }

    @Requires(property = "spec.name", value = "BlockingRolesFinderSpec")
    @Controller("/echo")
    static class EchoController {
        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Get
        Map<String, String> index(Principal principal) {
            return Map.of("username", principal.name)
        }
    }

    @Requires(property = "spec.name", value = "BlockingRolesFinderSpec")
    @Controller("/roles")
    static class RolesController {
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get
        Map<String, List<String>> roles() {
            return Map.of("roles", Collections.singletonList("ROLE_ADMIN"))
        }
    }

    @Requires(property = "spec.name", value = "BlockingRolesFinderSpec")
    @Singleton
    @Replaces(RolesFinder.class)
    static class BlockingRolesFinder implements RolesFinder {
        @Inject @Client("/") HttpClient httpClient
        @Override
        List<String> resolveRoles(Map<String, Object> attributes) {
            Map<String, List<String>> m = Mono.from(httpClient.retrieve(HttpRequest.GET("/roles"),
                    Argument.mapOf(Argument.of(String.class), Argument.listOf(String.class)))).block();
            return m.get("roles");
        }
    }
}