package io.micronaut.security.oauth2.endpoint.authorization.response

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.context.event.ApplicationEventListener
import io.micronaut.core.util.CollectionUtils
import io.micronaut.core.util.StringUtils
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.MutableHttpRequest
import io.micronaut.http.annotation.Consumes
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Post
import io.micronaut.http.annotation.Produces
import io.micronaut.http.annotation.Status
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.http.cookie.Cookie
import io.micronaut.http.server.util.HttpHostResolver
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.event.LoginFailedEvent
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse
import io.micronaut.security.rules.SecurityRule
import jakarta.inject.Singleton
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

import java.util.concurrent.CopyOnWriteArrayList

/**
 * When the ID token returned by the token endpoint does not pass validation, the authorization callback must go
 * through the login failure handler and publish a {@link LoginFailedEvent}, like every other authentication failure.
 */
class OpenIdCallbackIdTokenValidationFailureSpec extends Specification {

    private static final String ID_TOKEN_VALIDATION_FAILED = "ID token validation failed"

    @Shared
    @AutoCleanup
    EmbeddedServer oauthServer = ApplicationContext.run(EmbeddedServer, [
            "spec.name": "AuthServerOpenIdCallbackIdTokenValidationFailureSpec",
    ] as Map<String, Object>)

    @Shared
    @AutoCleanup
    EmbeddedServer redirectServer = ApplicationContext.run(EmbeddedServer, clientConfiguration(true))

    @Shared
    @AutoCleanup
    EmbeddedServer noRedirectServer = ApplicationContext.run(EmbeddedServer, clientConfiguration(false))

    @Shared
    @AutoCleanup
    HttpClient redirectClient = redirectServer.applicationContext.createBean(HttpClient, redirectServer.URL)

    @Shared
    @AutoCleanup
    HttpClient noRedirectClient = noRedirectServer.applicationContext.createBean(HttpClient, noRedirectServer.URL)

    private Map<String, Object> clientConfiguration(boolean redirect) {
        [
                "spec.name": "OpenIdCallbackIdTokenValidationFailureSpec",
                "micronaut.security.authentication": "cookie",
                "micronaut.security.redirect.enabled": redirect ? StringUtils.TRUE : StringUtils.FALSE,
                "micronaut.security.redirect.login-failure": "/login-failed",
                "micronaut.http.client.followRedirects": false,
                "micronaut.security.oauth2.clients.auth.openid.issuer": "http://localhost:${oauthServer.port}/oauth2/default".toString(),
                "micronaut.security.oauth2.clients.auth.client-id": "xxx",
                "micronaut.security.oauth2.clients.auth.client-secret": "xxx",
        ] as Map<String, Object>
    }

    @Unroll
    void "#description ID token with redirects enabled redirects to the login failure URL and publishes a LoginFailedEvent"(String description, boolean signed) {
        given:
        AuthServerController authServer = oauthServer.applicationContext.getBean(AuthServerController)
        authServer.signedIdToken = signed
        LoginFailedEventListener listener = redirectServer.applicationContext.getBean(LoginFailedEventListener)
        listener.events.clear()

        when:
        HttpResponse<?> response = callback(redirectClient.toBlocking(), authServer)

        then:
        HttpStatus.SEE_OTHER == response.status()
        '/login-failed' == response.getHeaders().get(HttpHeaders.LOCATION)

        and:
        1 == listener.events.size()
        ID_TOKEN_VALIDATION_FAILED == ((AuthenticationResponse) listener.events[0].source).message.orElse(null)

        where:
        description               | signed
        'unparseable'             | false
        'signed with unknown key' | true
    }

    @Unroll
    void "#description ID token with redirects disabled responds 401 and publishes a LoginFailedEvent"(String description, boolean signed) {
        given:
        AuthServerController authServer = oauthServer.applicationContext.getBean(AuthServerController)
        authServer.signedIdToken = signed
        LoginFailedEventListener listener = noRedirectServer.applicationContext.getBean(LoginFailedEventListener)
        listener.events.clear()

        when:
        callback(noRedirectClient.toBlocking(), authServer)

        then:
        HttpClientResponseException e = thrown()
        HttpStatus.UNAUTHORIZED == e.status

        and:
        1 == listener.events.size()
        ID_TOKEN_VALIDATION_FAILED == ((AuthenticationResponse) listener.events[0].source).message.orElse(null)

        where:
        description               | signed
        'unparseable'             | false
        'signed with unknown key' | true
    }

    private static HttpResponse<?> callback(BlockingHttpClient client, AuthServerController authServer) {
        HttpResponse<?> response = client.exchange(HttpRequest.GET("/oauth/login/auth"))
        assert HttpStatus.FOUND == response.status()
        Map<String, Cookie> cookieJar = [:]
        response.getCookies().all.each { Cookie cookie -> cookieJar[cookie.name] = cookie }
        client.exchange(HttpRequest.GET(response.getHeaders().get(HttpHeaders.LOCATION)))
        assert authServer.state

        MutableHttpRequest<?> request = HttpRequest.POST("/oauth/callback/auth",
                CollectionUtils.mapOf("code", "xxx", "state", authServer.state))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        cookieJar.values().each { Cookie cookie -> request.cookie(Cookie.of(cookie.name, cookie.value)) }
        client.exchange(request)
    }

    @Requires(property = "spec.name", value = "OpenIdCallbackIdTokenValidationFailureSpec")
    @Singleton
    static class LoginFailedEventListener implements ApplicationEventListener<LoginFailedEvent> {
        final List<LoginFailedEvent> events = new CopyOnWriteArrayList<>()

        @Override
        void onApplicationEvent(LoginFailedEvent event) {
            events.add(event)
        }
    }

    @Requires(property = "spec.name", value = "OpenIdCallbackIdTokenValidationFailureSpec")
    @Controller
    static class HomeController {
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Status(HttpStatus.I_AM_A_TEAPOT)
        void index() {
        }
    }

    @Requires(property = "spec.name", value = "AuthServerOpenIdCallbackIdTokenValidationFailureSpec")
    @Secured(SecurityRule.IS_ANONYMOUS)
    @Controller
    static class AuthServerController {
        private final HttpHostResolver httpHostResolver
        private final RSAKey publishedKey = new RSAKeyGenerator(2048).algorithm(JWSAlgorithm.RS256).keyID("published").generate()
        private final RSAKey unpublishedKey = new RSAKeyGenerator(2048).algorithm(JWSAlgorithm.RS256).keyID("unpublished").generate()
        String state
        String nonce
        boolean signedIdToken

        AuthServerController(HttpHostResolver httpHostResolver) {
            this.httpHostResolver = httpHostResolver
        }

        @Consumes(MediaType.TEXT_HTML)
        @Get("/oauth2/default/v1/authorize")
        @Status(HttpStatus.OK)
        void authorized(HttpRequest<?> request) {
            state = request.getParameters().get("state")
            nonce = request.getParameters().get("nonce")
        }

        @Produces(MediaType.APPLICATION_JSON)
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Post("/oauth2/default/v1/token")
        @Status(HttpStatus.OK)
        HttpResponse<?> token(HttpRequest<?> request) {
            String host = httpHostResolver.resolve(request)
            OpenIdTokenResponse openIdTokenResponse = new OpenIdTokenResponse()
            openIdTokenResponse.setIdToken(signedIdToken ? idTokenSignedWithUnpublishedKey(host) : "not-a-jwt")
            openIdTokenResponse.setAccessToken("access-token")
            openIdTokenResponse.setTokenType("Bearer")
            HttpResponse.ok(openIdTokenResponse)
        }

        private String idTokenSignedWithUnpublishedKey(String host) {
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(host + "/oauth2/default")
                    .audience("xxx")
                    .subject("john")
                    .claim("nonce", nonce)
                    .issueTime(new Date())
                    .expirationTime(new Date(System.currentTimeMillis() + 60_000))
                    .build()
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(publishedKey.keyID).build(), claims)
            jwt.sign(new RSASSASigner(unpublishedKey))
            jwt.serialize()
        }

        @Produces(MediaType.APPLICATION_JSON)
        @Get("/oauth2/default/v1/keys")
        String keys() {
            new JWKSet(publishedKey.toPublicJWK()).toString()
        }

        @Get("/oauth2/default/.well-known/openid-configuration")
        String openIdConfiguration(HttpRequest<?> request) {
            String host = httpHostResolver.resolve(request)
            '{"issuer":"' + host + '/oauth2/default","authorization_endpoint":"' + host + '/oauth2/default/v1/authorize","token_endpoint":"' + host + '/oauth2/default/v1/token","jwks_uri":"' + host + '/oauth2/default/v1/keys","response_types_supported":["code"],"grant_types_supported":["authorization_code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"scopes_supported":["openid","profile","email"],"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post"],"claims_supported":["iss","sub","aud","iat","exp","nonce"],"code_challenge_methods_supported":["S256"]}'
        }
    }
}
