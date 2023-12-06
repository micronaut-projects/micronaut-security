package io.micronaut.security.authorization

import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.NonNull
import io.micronaut.core.annotation.Nullable
import io.micronaut.core.async.annotation.SingleResult
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.inject.ExecutableMethod
import io.micronaut.management.endpoint.EndpointSensitivityProcessor
import io.micronaut.management.endpoint.annotation.Endpoint
import io.micronaut.management.endpoint.annotation.Read
import io.micronaut.security.FailedAuthenticationScenario
import io.micronaut.security.MockAuthenticationProvider
import io.micronaut.security.SuccessAuthenticationScenario
import io.micronaut.security.annotation.Secured
import io.micronaut.security.annotation.User
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.AuthenticationArgumentBinder
import io.micronaut.security.authentication.AuthenticationFailureReason
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.ClientAuthentication
import io.micronaut.security.authentication.PrincipalArgumentBinder
import io.micronaut.security.authentication.ServerAuthentication
import io.micronaut.security.authentication.UserArgumentBinder
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.rules.SecurityRuleResult
import io.micronaut.security.rules.SensitiveEndpointRule
import io.micronaut.security.testutils.EmbeddedServerSpecification
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono

import java.security.Principal

class AuthorizationSpec extends EmbeddedServerSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'endpoints.beans.enabled': true,
                'endpoints.beans.sensitive': true,
                'micronaut.security.intercept-url-map': [
                        [pattern: '/urlMap/admin', access: ['ROLE_ADMIN', 'ROLE_X']],
                        [pattern: '/urlMap/**',    access: 'isAuthenticated()'],
                        [pattern: '/anonymous/**', access: 'isAnonymous()'],
                ]
        ]
    }

    @Override
    String getSpecName() {
        'AuthorizationSpec'
    }

    void "test /beans is secured"() {
        when:
        client.exchange(HttpRequest.GET("/beans"))

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.UNAUTHORIZED
    }

    void "test accessing an anonymous without authentication"() {
        when:
        HttpResponse<String> response = client.exchange(HttpRequest.GET("/anonymous/hello"), String)

        then:
        response.body() == 'You are anonymous'
    }

    void "java.security.Principal Argument Binders binds even if Optional<Principal>"() {
        expect:
        embeddedServer.applicationContext.getBean(PrincipalArgumentBinder.class)

        when:
        HttpResponse<String> response = client.exchange(HttpRequest.GET("/anonymous/hello")
                .basicAuth("valid", "password"), String)

        then:
        response.body() == 'You are valid'
    }

    void "Authentication Argument Binders binds Principal if return type is Single"() {
        expect:
        embeddedServer.applicationContext.getBean(PrincipalArgumentBinder.class)

        when:
        HttpResponse<String> response = client.exchange(HttpRequest.GET("/argumentbinder/singleprincipal")
                .basicAuth("valid", "password"), String)

        then:
        response.body() == 'You are valid'
    }

    void "Authentication Argument Binders binds Authentication if return type is Single"() {
        expect:
        embeddedServer.applicationContext.getBean(AuthenticationArgumentBinder.class)

        when:
        HttpResponse<String> response = client.exchange(HttpRequest.GET("/argumentbinder/singleauthentication")
                .basicAuth("valid", "password"), String)

        then:
        response.body() == 'You are valid'
    }

    void "Authentication Argument Binders binds annotated subtype of Principal"() {
        expect:
        embeddedServer.applicationContext.getBean(UserArgumentBinder.class)

        when:
        HttpResponse<String> response = client.exchange(HttpRequest.GET("/subtypeargumentbinder/single-server-authentication")
                .basicAuth("valid", "password"), String)

        then:
        response.body() == 'You are valid'
    }

    void "Authentication Argument Binders cannot bind annotated subtype of Principal if subtype doesn't match request.getPrincipal"() {
        expect:
        embeddedServer.applicationContext.containsBean(UserArgumentBinder.class)

        when:
        client.exchange(HttpRequest.GET("/subtypeargumentbinder/single-client-authentication")
                .basicAuth("valid", "password"), String)

        then:
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.BAD_REQUEST
    }

    void "Authentication Argument Binders cannot bind non-annotated subtype of Principal"() {
        expect:
        embeddedServer.applicationContext.getBean(UserArgumentBinder.class)

        when:
        client.exchange(HttpRequest.GET("/subtypeargumentbinder/single-no-user-authentication")
                .basicAuth("valid", "password"), String)

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.BAD_REQUEST
    }

    void "Authentication Argument Binders binds annotated custom subtype of Principal"() {
        expect:
        embeddedServer.applicationContext.getBean(UserArgumentBinder.class)

        when:
        HttpResponse<String> response = client.exchange(HttpRequest.GET("/customuserargumentbinder/single-user")
                .basicAuth("custom", "password"), String)

        then:
        response.body() == 'You are custom'
    }

    void "test accessing the url map controller without authentication"() {
        when:
        client.exchange(HttpRequest.GET("/urlMap/authenticated"))

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.UNAUTHORIZED
    }

    void "test accessing the url map controller"() {
        when:
        HttpResponse<String> response = client.exchange(HttpRequest.GET("/urlMap/authenticated")
                .basicAuth("valid", "password"), String)
        then:
        response.body() == "valid is authenticated"
    }

    void "test accessing the url map controller and bind to java.util.Principal"() {
        when:
        HttpResponse<String> response = client.exchange(HttpRequest.GET("/urlMap/principal")
                .basicAuth("valid", "password"), String)

        then:
        response.body() == "valid is authenticated"
    }

    void "test accessing the url map admin action without the required role"() {
        when:
        client.exchange(HttpRequest.GET("/urlMap/admin")
                .basicAuth("valid", "password"), String)


        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.FORBIDDEN
    }

    void "test accessing the url map admin action with the required role"() {
        when:
        HttpResponse<String> response = client.exchange(HttpRequest.GET("/urlMap/admin")
                .basicAuth("admin", "password"), String)

        then:
        response.body() == "You have admin"
    }

    void "test accessing the secured controller without authentication"() {when:
        when:
        client.exchange(HttpRequest.GET("/secured/authenticated"))

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.UNAUTHORIZED
    }

    void "test accessing the secured controller"() {
        when:
        HttpResponse<String> response = client.exchange(HttpRequest.GET("/secured/authenticated")
                .basicAuth("valid", "password"), String)

        then:
        response.body() == "valid is authenticated"
    }

    void "test accessing the secured admin action without the required role"() {
        when:
        client.exchange(HttpRequest.GET("/secured/admin")
                .basicAuth("valid", "password"), String)

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.FORBIDDEN
    }

    void "test accessing the secured admin action with the required role"() {
        when:
        HttpResponse<String> response = client.exchange(HttpRequest.GET("/secured/admin")
                .basicAuth("admin", "password"), String)

        then:
        response.body() == "You have admin"
    }

    void "test accessing a controller without a rule"() {
        when:
        client.exchange(HttpRequest.GET("/noRule/index")
                .basicAuth("valid", "password"), String)

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.FORBIDDEN
    }

    void "test accessing a non sensitive endpoint without authentication"() {
        when:
        HttpResponse<String> response = client.exchange(HttpRequest.GET("/non-sensitive"), String)

        then:
        response.body() == "Not logged in"
    }

    void "test accessing a non sensitive endpoint with authentication"() {
        when:
        HttpResponse<String> response = client.exchange(HttpRequest.GET("/non-sensitive")
                .basicAuth("valid", "password"), String)

        then:
        response.body() == "Logged in as valid"
    }

    void "test accessing a sensitive endpoint without authentication"() {
        when:
        client.exchange(HttpRequest.GET("/sensitive"), String)

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status == HttpStatus.UNAUTHORIZED
    }

    void "test accessing a sensitive endpoint with authentication"() {
        when:
        HttpResponse<String> response = client.exchange(HttpRequest.GET("/sensitive")
                .basicAuth("valid", "password"), String)
        then:
        response.body() == "Hello valid"
    }

    void "test accessing a sensitive endpoint with Authentication binded with authentication"() {
        when:
        HttpResponse<String> response = client.exchange(HttpRequest.GET("/sensitiveauthentication")
                .basicAuth("valid", "password"), String)
        then:
        response.body() == "Hello valid"
    }

    @Requires(property = 'spec.name', value = 'AuthorizationSpec')
    @Controller("/noRule")
    static class NoRuleController {

        @Get("/index")
        String index() {
            "index"
        }
    }

    @Requires(property = 'spec.name', value = 'AuthorizationSpec')
    @Controller('/anonymous')
    static class AnonymousController {

        @Get("/hello")
        String hello(@Nullable Principal principal) {
            "You are ${principal != null ? principal.getName() : 'anonymous'}"
        }
    }

    @Requires(property = 'spec.name', value = 'AuthorizationSpec')
    @Endpoint(id = "nonSensitive", defaultSensitive = false)
    static class NonSensitiveEndpoint {

        @Read
        String hello(@Nullable Principal principal) {
            if (principal == null) {
                "Not logged in"
            } else {
                "Logged in as ${principal.name}"
            }
        }
    }

    @Requires(property = 'spec.name', value = 'AuthorizationSpec')
    @Endpoint(id = "sensitive", defaultSensitive = true)
    static class SensitiveEndpoint {
        @Read
        String hello(Principal principal) {
            "Hello ${principal.name}"
        }
    }

    @Requires(property = 'spec.name', value = 'AuthorizationSpec')
    @Controller("/secured")
    @Secured(SecurityRule.IS_AUTHENTICATED)
    static class SecuredController {

        @Get("/admin")
        @Secured(["ROLE_ADMIN", "ROLE_X"])
        String admin() {
            "You have admin"
        }

        @Get("/authenticated")
        String authenticated(Authentication authentication) {
            "${authentication.getName()} is authenticated"
        }
    }

    @Requires(property = 'spec.name', value = 'AuthorizationSpec')
    @Controller('/argumentbinder')
    @Secured("isAuthenticated()")
    static class PrincipalArgumentBinderController {

        @Get("/singleprincipal")
        @SingleResult
        Publisher<String> singlehello(Principal principal) {
            Mono.just("You are ${principal.getName()}".toString())
        }

        @Get("/singleauthentication")
        @SingleResult
        Publisher<String> singleauthentication(Authentication authentication) {
            Mono.just("You are ${authentication.getName()}".toString())
        }
    }

    @Requires(property = 'spec.name', value = 'AuthorizationSpec')
    @Controller('/subtypeargumentbinder')
    @Secured("isAuthenticated()")
    static class PrincipalSubtypeArgumentBinderController {

        @Get("/single-server-authentication")
        @SingleResult
        Publisher<String> singleServerAuthentication(@User ServerAuthentication authentication) {
            Mono.just("You are ${authentication.getName()}".toString())
        }

        @Get("/single-client-authentication")
        @SingleResult
        Publisher<String> singleClientAuthentication(@User ClientAuthentication authentication) {
            Mono.just("You are ${authentication.getName()}".toString())
        }

        @Get("/single-no-user-authentication")
        @SingleResult
        Publisher<String> singleNoUserAuthentication(ServerAuthentication authentication) {
            Mono.just("You are ${authentication.getName()}".toString())
        }
    }

    @Requires(property = 'spec.name', value = 'AuthorizationSpec')
    @Controller('/customuserargumentbinder')
    @Secured("isAuthenticated()")
    static class CustomUserArgumentBinderController {

        @Get("/single-user")
        @SingleResult
        Publisher<String> singleServerAuthentication(@User TestingAuthenticationProvider.CustomAuthentication authentication) {
            Mono.just("You are ${authentication.getName()}".toString())
        }
    }

    @Requires(property = 'spec.name', value = 'AuthorizationSpec')
    @Controller("/urlMap")
    static class UrlMapController {

        @Get("/admin")
        String admin() {
            "You have admin"
        }

        @Get("/authenticated")
        String authenticated(Authentication authentication) {
            "${authentication.name} is authenticated"
        }

        @Get("/principal")
        String authenticated(Principal principal) {
            "${principal.name} is authenticated"
        }
    }

    @Requires(property = 'spec.name', value = 'AuthorizationSpec')
    @Singleton
    static class TestingAuthenticationProvider extends MockAuthenticationProvider {
        TestingAuthenticationProvider() {
            super([
                    new SuccessAuthenticationScenario("valid","password"),
                    new SuccessAuthenticationScenario("custom", "password"),
                    new SuccessAuthenticationScenario("admin",["ROLE_ADMIN"])
            ], [
                    new FailedAuthenticationScenario("disabled", AuthenticationFailureReason.USER_DISABLED),
                    new FailedAuthenticationScenario("accountExpired", AuthenticationFailureReason.ACCOUNT_EXPIRED),
                    new FailedAuthenticationScenario("passwordExpired", AuthenticationFailureReason.PASSWORD_EXPIRED),
                    new FailedAuthenticationScenario("accountLocked", AuthenticationFailureReason.ACCOUNT_LOCKED),
                    new FailedAuthenticationScenario("invalidPassword", AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH),
            ])
        }

        @Override
        Publisher<AuthenticationResponse> authenticate(Object httpRequest, AuthenticationRequest authenticationRequest) {
            return Flux.from(super.authenticate(httpRequest, authenticationRequest)).map(response -> {
                if (response.authenticated && response.getAuthentication().orElseThrow().name == 'custom') {
                    return new CustomAuthenticationResponse('custom')
                }
                return response
            })
        }

        static class CustomAuthenticationResponse implements AuthenticationResponse {

            private final String username

            CustomAuthenticationResponse(String username) {
                this.username = username
            }

            @Override
            Optional<Authentication> getAuthentication() {
                return Optional.of(new CustomAuthentication(this.username, Collections.emptyList(), Collections.emptyMap()))
            }
        }

        static class CustomAuthentication extends ServerAuthentication {
            CustomAuthentication(String name, Collection<String> roles, Map<String, Object> attributes) {
                super(name, roles, attributes)
            }
        }
    }

    @Requires(property = 'spec.name', value = 'AuthorizationSpec')
    @Endpoint(id = "sensitiveauthentication", defaultSensitive = true)
    static class SensitiveWithAuthenticationEndpoint {

        @Read
        String hello(Authentication authentication) {
            "Hello ${authentication.name}"
        }
    }

    @Requires(property = 'spec.name', value = 'AuthorizationSpec')
    @Replaces(SensitiveEndpointRule.class)
    @Singleton
    static class SensitiveEndpointRuleReplacement extends SensitiveEndpointRule {
        SensitiveEndpointRuleReplacement(EndpointSensitivityProcessor endpointSensitivityProcessor) {
            super(endpointSensitivityProcessor)
        }
        @Override
        protected Publisher<SecurityRuleResult> checkSensitiveAuthenticated(@NonNull HttpRequest<?> request,
                                                                            @NonNull Authentication authentication,
                                                                            @NonNull ExecutableMethod<?, ?> method) {
            Mono.just(SecurityRuleResult.ALLOWED)
        }
    }
}
