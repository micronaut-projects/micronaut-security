package io.micronaut.security.authorization

import io.micronaut.core.annotation.Nullable
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.management.endpoint.annotation.Endpoint
import io.micronaut.management.endpoint.annotation.Read
import io.micronaut.security.EmbeddedServerSpecification
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.AuthenticationException
import io.micronaut.security.authentication.AuthenticationFailed
import io.micronaut.security.authentication.AuthenticationFailureReason
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.PrincipalArgumentBinder
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.rules.SecurityRule
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import io.reactivex.Single
import org.reactivestreams.Publisher

import javax.inject.Singleton
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
        embeddedServer.applicationContext.getBean(PrincipalArgumentBinder.class)

        when:
        HttpResponse<String> response = client.exchange(HttpRequest.GET("/argumentbinder/singleauthentication")
                .basicAuth("valid", "password"), String)

        then:
        response.body() == 'You are valid'
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
        Single<String> singlehello(Principal principal) {
            Single.just("You are ${principal.getName()}") as Single<String>
        }

        @Get("/singleauthentication")
        Single<String> singleauthentication(Authentication authentication) {
            Single.just("You are ${authentication.getName()}") as Single<String>
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
    static class TestingAuthenticationProvider implements AuthenticationProvider {

        @Override
        Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            Flowable.create({ emitter ->
                String username = authenticationRequest.getIdentity().toString()
                AuthenticationFailed authenticationFailed = null
                if (username == "disabled") {
                    authenticationFailed = new AuthenticationFailed(AuthenticationFailureReason.USER_DISABLED)

                } else if (username == "accountExpired") {
                    authenticationFailed = new AuthenticationFailed(AuthenticationFailureReason.ACCOUNT_EXPIRED)

                } else if (username == "passwordExpired") {
                    authenticationFailed = new AuthenticationFailed(AuthenticationFailureReason.PASSWORD_EXPIRED)

                } else if (username == "accountLocked") {
                    authenticationFailed = new AuthenticationFailed(AuthenticationFailureReason.ACCOUNT_LOCKED)

                } else if (username == "invalidPassword") {
                    authenticationFailed = new AuthenticationFailed(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH)

                } else if (username == "notFound") {

                }

                if (authenticationFailed) {
                    emitter.onError(new AuthenticationException(authenticationFailed))
                } else {
                    emitter.onNext(new UserDetails(username, (username == "admin") ?  ["ROLE_ADMIN"] : ["foo", "bar"]));
                    emitter.onComplete()
                }
            }, BackpressureStrategy.ERROR)
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
}
