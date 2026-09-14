package io.micronaut.security.oauth2.endpoint.authorization.response

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.context.exceptions.ConfigurationException
import io.micronaut.core.util.CollectionUtils
import io.micronaut.core.util.StringUtils
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.MutableHttpRequest
import io.micronaut.http.annotation.Body
import io.micronaut.http.annotation.Consumes
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Post
import io.micronaut.http.annotation.Produces
import io.micronaut.http.annotation.Status
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.cookie.Cookie
import io.micronaut.http.server.util.HttpHostResolver
import io.micronaut.runtime.context.scope.Refreshable
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.oauth2.endpoint.authorization.pkce.S256PkceGenerator
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse
import io.micronaut.security.oauth2.grants.AuthorizationCodeGrant
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.token.Claims
import io.micronaut.security.token.generator.AccessRefreshTokenGenerator
import io.micronaut.security.token.jwt.endpoints.JwkProvider
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureConfiguration
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureGeneratorConfiguration
import io.micronaut.security.token.render.AccessRefreshToken
import jakarta.inject.Named
import jakarta.inject.Singleton
import org.jspecify.annotations.NonNull
import org.jspecify.annotations.Nullable
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.text.ParseException

import static com.nimbusds.jose.jwk.KeyUse.SIGNATURE

/**
 * The state, PKCE code verifier and nonce persisted in cookies during the authorization redirect are
 * single-use values. Once the authorization callback has consumed them the callback response must expire
 * the cookies so a replayed callback is rejected.
 */
class OpenIdCallbackExpiresCookiesSpec extends Specification {

    private static final List<String> ONE_TIME_COOKIES = ['OAUTH2_STATE', 'OAUTH2_PKCE', 'OPENID_NONCE']

    @Shared
    @AutoCleanup
    EmbeddedServer oauthServer = ApplicationContext.run(EmbeddedServer, [
            "spec.name": "AuthServerOpenIdCallbackExpiresCookiesSpec",
    ] as Map<String, Object>)

    @Shared
    @AutoCleanup
    EmbeddedServer server = ApplicationContext.run(EmbeddedServer, [
            "spec.name": "OpenIdCallbackExpiresCookiesSpec",
            "micronaut.security.authentication": "cookie",
            "micronaut.security.oauth2.pkce.persistence": "cookie",
            'micronaut.http.client.followRedirects': false,
            "micronaut.security.oauth2.clients.auth.openid.issuer": "http://localhost:${oauthServer.port}/oauth2/default".toString(),
            "micronaut.security.oauth2.clients.auth.client-id": "xxx",
            "micronaut.security.oauth2.clients.auth.client-secret": "xxx",
            "micronaut.security.redirect.login-failure": "/login-failed",
    ] as Map<String, Object>)

    @Shared
    @AutoCleanup
    HttpClient httpClient = server.applicationContext.createBean(HttpClient, server.URL)

    void "successful callback expires the state, PKCE and nonce cookies and the same state cannot be replayed"() {
        given:
        BlockingHttpClient client = httpClient.toBlocking()
        AuthServerController authServer = oauthServer.applicationContext.getBean(AuthServerController)

        when: 'starting the login flow sets the state, PKCE and nonce cookies'
        HttpResponse<?> response = client.exchange(HttpRequest.GET("/oauth/login/auth"))
        Map<String, Cookie> cookieJar = cookiesOf(response)

        then:
        HttpStatus.FOUND == response.status()
        ONE_TIME_COOKIES.every { cookieJar.containsKey(it) }
        ONE_TIME_COOKIES.every { cookieJar[it].maxAge > 0 }

        when: 'the browser follows the redirect to the authorization server'
        client.exchange(HttpRequest.GET(response.getHeaders().get(HttpHeaders.LOCATION)))

        then:
        authServer.state
        authServer.nonce

        when: 'the authorization server calls back with a valid code and state'
        response = client.exchange(callbackRequest(authServer.state, cookieJar))

        then: 'the login succeeds'
        HttpStatus.SEE_OTHER == response.status()
        '/' == response.getHeaders().get(HttpHeaders.LOCATION)

        and: 'the callback response expires every one-time cookie with the configured path and attributes'
        ONE_TIME_COOKIES.every { name -> expiringSetCookieHeader(response, name) }
        ONE_TIME_COOKIES.every { name ->
            String header = expiringSetCookieHeader(response, name)
            header.contains('Path=/') && header.toLowerCase().contains('httponly')
        }

        when: 'a browser honouring the expiry no longer holds the one-time cookies'
        applySetCookies(cookieJar, response)

        then:
        ONE_TIME_COOKIES.every { !cookieJar.containsKey(it) }

        when: 'the same callback is replayed with the remaining cookies'
        response = client.exchange(callbackRequest(authServer.state, cookieJar))

        then: 'the replay is rejected because the stored state is gone'
        HttpStatus.SEE_OTHER == response.status()
        '/login-failed' == response.getHeaders().get(HttpHeaders.LOCATION)
    }

    void "failed callback also expires the state, PKCE and nonce cookies"() {
        given:
        BlockingHttpClient client = httpClient.toBlocking()
        AuthServerController authServer = oauthServer.applicationContext.getBean(AuthServerController)

        when: 'a first login flow produces a well-formed state'
        HttpResponse<?> response = client.exchange(HttpRequest.GET("/oauth/login/auth"))
        client.exchange(HttpRequest.GET(response.getHeaders().get(HttpHeaders.LOCATION)))
        String staleState = authServer.state

        and: 'a second login flow sets fresh state, PKCE and nonce cookies'
        response = client.exchange(HttpRequest.GET("/oauth/login/auth"))
        Map<String, Cookie> cookieJar = cookiesOf(response)
        client.exchange(HttpRequest.GET(response.getHeaders().get(HttpHeaders.LOCATION)))

        then:
        ONE_TIME_COOKIES.every { cookieJar.containsKey(it) }
        staleState != authServer.state

        when: 'the callback carries the stale state which does not match the persisted one'
        response = client.exchange(callbackRequest(staleState, cookieJar))

        then: 'the login fails'
        HttpStatus.SEE_OTHER == response.status()
        '/login-failed' == response.getHeaders().get(HttpHeaders.LOCATION)

        and: 'the one-time cookies are expired anyway'
        ONE_TIME_COOKIES.every { name -> expiringSetCookieHeader(response, name) }
    }

    void "callback without the one-time cookies does not emit expiring cookies"() {
        given:
        BlockingHttpClient client = httpClient.toBlocking()

        when:
        HttpResponse<?> response = client.exchange(callbackRequest("unknown", [:]))

        then:
        HttpStatus.SEE_OTHER == response.status()
        '/login-failed' == response.getHeaders().get(HttpHeaders.LOCATION)
        response.getHeaders().getAll(HttpHeaders.SET_COOKIE).every { String header ->
            ONE_TIME_COOKIES.every { name -> !header.startsWith(name + '=') }
        }
    }

    private static MutableHttpRequest<?> callbackRequest(String state, Map<String, Cookie> cookieJar) {
        MutableHttpRequest<?> request = HttpRequest.POST("/oauth/callback/auth",
                CollectionUtils.mapOf("code", "xxx", "state", state))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        cookieJar.values().each { Cookie cookie -> request.cookie(Cookie.of(cookie.name, cookie.value)) }
        request
    }

    private static Map<String, Cookie> cookiesOf(HttpResponse<?> response) {
        Map<String, Cookie> jar = [:]
        applySetCookies(jar, response)
        jar
    }

    /**
     * Emulates a browser cookie jar: stores cookies set by the response and drops those whose max age is zero.
     */
    private static void applySetCookies(Map<String, Cookie> jar, HttpResponse<?> response) {
        response.getCookies().all.each { Cookie cookie ->
            if (cookie.maxAge == 0L) {
                jar.remove(cookie.name)
            } else {
                jar[cookie.name] = cookie
            }
        }
    }

    @Nullable
    private static String expiringSetCookieHeader(HttpResponse<?> response, String cookieName) {
        response.getHeaders().getAll(HttpHeaders.SET_COOKIE).find { String header ->
            header.startsWith(cookieName + '=') && header.toLowerCase().contains('max-age=0')
        }
    }

    @Requires(property = "spec.name", value = "OpenIdCallbackExpiresCookiesSpec")
    @Controller
    static class HomeController {
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Status(HttpStatus.I_AM_A_TEAPOT)
        void index() {
        }
    }

    @Requires(property = "spec.name", value = "AuthServerOpenIdCallbackExpiresCookiesSpec")
    @Secured(SecurityRule.IS_ANONYMOUS)
    @Controller
    static class AuthServerController {
        private final HttpHostResolver httpHostResolver
        String codeChallenge
        String state
        String nonce
        AccessRefreshTokenGenerator accessRefreshTokenGenerator

        AuthServerController(HttpHostResolver httpHostResolver, AccessRefreshTokenGenerator accessRefreshTokenGenerator) {
            this.httpHostResolver = httpHostResolver
            this.accessRefreshTokenGenerator = accessRefreshTokenGenerator
        }

        @Consumes(MediaType.TEXT_HTML)
        @Get("/oauth2/default/v1/authorize")
        @Status(HttpStatus.OK)
        void authorized(HttpRequest<?> request) {
            codeChallenge = request.getParameters().get("code_challenge")
            state = request.getParameters().get("state")
            nonce = request.getParameters().get("nonce")
        }

        @Produces(MediaType.APPLICATION_JSON)
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Post("/oauth2/default/v1/token")
        @Status(HttpStatus.OK)
        HttpResponse<?> token(HttpRequest<?> request, @Body AuthorizationCodeGrant codeGrant) {
            String host = httpHostResolver.resolve(request)
            String codeVerifier = codeGrant.getCodeVerifier()
            if (StringUtils.isEmpty(codeVerifier)) {
                return HttpResponse.unprocessableEntity()
            }
            if (!S256PkceGenerator.hash(codeVerifier).equals(codeChallenge)) {
                return HttpResponse.unprocessableEntity()
            }
            AccessRefreshToken accessRefreshToken = accessRefreshTokenGenerator.generate(Authentication.build("john", Collections.emptyList(),
                    CollectionUtils.mapOf(Claims.ISSUER, host + "/oauth2/default",
                            Claims.AUDIENCE, Collections.singletonList("xxx"),
                            OpenIdClaims.CLAIMS_NONCE, nonce))).get()
            OpenIdTokenResponse openIdTokenResponse = new OpenIdTokenResponse()
            openIdTokenResponse.setIdToken(accessRefreshToken.getAccessToken())
            openIdTokenResponse.setAccessToken(accessRefreshToken.getAccessToken())
            openIdTokenResponse.setTokenType("Bearer")
            HttpResponse.ok(openIdTokenResponse)
        }

        @Get("/oauth2/default/.well-known/openid-configuration")
        String openIdConfiguration(HttpRequest<?> request) {
            String host = httpHostResolver.resolve(request)
            '{"issuer":"' + host + '/oauth2/default","authorization_endpoint":"' + host + '/oauth2/default/v1/authorize","token_endpoint":"' + host + '/oauth2/default/v1/token","userinfo_endpoint":"' + host + '/oauth2/default/v1/userinfo","registration_endpoint":"' + host + '/oauth2/v1/clients","jwks_uri":"' + host + '/keys","response_types_supported":["code","id_token","code id_token","code token","id_token token","code id_token token"],"response_modes_supported":["query","fragment","form_post","okta_post_message"],"grant_types_supported":["authorization_code","implicit","refresh_token","password"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"scopes_supported":["openid","profile","email","address","phone","offline_access"],"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"claims_supported":["iss","ver","sub","aud","iat","exp","jti","auth_time","amr","idp","nonce","name","nickname","preferred_username","given_name","middle_name","family_name","email","email_verified","profile","zoneinfo","locale","address","phone_number","picture","website","gender","birthdate","updated_at","at_hash","c_hash"],"code_challenge_methods_supported":["S256"],"introspection_endpoint":"' + host + '/oauth2/default/v1/introspect","introspection_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"revocation_endpoint":"' + host + '/oauth2/default/v1/revoke","revocation_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"end_session_endpoint":"' + host + '/oauth2/default/v1/logout","request_parameter_supported":true,"request_object_signing_alg_values_supported":["HS256","HS384","HS512","RS256","RS384","RS512","ES256","ES384","ES512"]}'
        }
    }

    static abstract class AbstractRSASignatureConfiguration implements RSASignatureConfiguration {

        private static final Logger LOG = LoggerFactory.getLogger(AbstractRSASignatureConfiguration.class)

        protected final JWK publicJWK
        protected final RSAPublicKey publicKey
        protected final RSAPrivateKey privateKey
        protected final JWSAlgorithm jwsAlgorithm

        AbstractRSASignatureConfiguration(String jsonJwk) {
            RSAKey primaryRSAKey = parseRSAKey(jsonJwk)
                    .orElseThrow(() -> new ConfigurationException("could not parse primary JWK to RSA Key"))

            publicJWK = primaryRSAKey.toPublicJWK()

            try {
                privateKey = primaryRSAKey.toRSAPrivateKey()
            } catch (JOSEException e) {
                throw new ConfigurationException("could not primary RSA private key")
            }

            try {
                publicKey = primaryRSAKey.toRSAPublicKey()
            } catch (JOSEException e) {
                throw new ConfigurationException("could not primary RSA public key")
            }

            jwsAlgorithm = parseJWSAlgorithm(primaryRSAKey)
                    .orElseThrow(() -> new ConfigurationException("could not parse JWS Algorithm from RSA Key"))
        }

        JWSAlgorithm getJwsAlgorithm() {
            return jwsAlgorithm
        }

        @NonNull
        JWK getPublicJWK() {
            return publicJWK
        }

        @Override
        RSAPublicKey getPublicKey() {
            return publicKey
        }

        @NonNull
        private static Optional<JWSAlgorithm> parseJWSAlgorithm(@NonNull RSAKey rsaKey) {
            Algorithm algorithm = rsaKey.getAlgorithm()
            if (algorithm == null) {
                return Optional.empty()
            }
            if (algorithm instanceof JWSAlgorithm) {
                return Optional.of((JWSAlgorithm) algorithm)
            }
            return Optional.of(JWSAlgorithm.parse(algorithm.getName()))
        }

        @NonNull
        private static Optional<RSAKey> parseRSAKey(@NonNull String jsonJwk) {
            try {
                JWK jwk = JWK.parse(jsonJwk)
                if (!(jwk instanceof RSAKey)) {
                    LOG.warn("JWK is not an RSAKey")
                    return Optional.empty()
                }
                return Optional.of((RSAKey) jwk)
            } catch (ParseException e) {
                LOG.warn("Could not parse JWK JSON string {}", jsonJwk)
                return Optional.empty()
            }
        }

        RSAPrivateKey getPrivateKey() {
            return this.privateKey
        }
    }

    @Requires(property = "spec.name", value = "AuthServerOpenIdCallbackExpiresCookiesSpec")
    @Refreshable
    @Named("generator")
    static class PrimarySignatureConfiguration extends AbstractRSASignatureConfiguration implements RSASignatureGeneratorConfiguration {

        PrimarySignatureConfiguration(RS256JsonWebKeyGenerator generator) {
            super(generator.generateJsonWebKey())
        }

        @Override
        RSAPrivateKey getPrivateKey() {
            return super.getPrivateKey()
        }

        @Override
        JWSAlgorithm getJwsAlgorithm() {
            return super.getJwsAlgorithm()
        }
    }

    @Requires(property = "spec.name", value = "AuthServerOpenIdCallbackExpiresCookiesSpec")
    @Singleton
    static class RS256JsonWebKeyGenerator {
        @NonNull
        String generateJsonWebKey() throws JOSEException {
            return new RSAKeyGenerator(2048)
                    .algorithm(JWSAlgorithm.RS256)
                    .keyUse(SIGNATURE)
                    .keyID(UUID.randomUUID().toString().replaceAll("-", ""))
                    .generate()
                    .toJSONString()
        }
    }

    @Requires(property = "spec.name", value = "AuthServerOpenIdCallbackExpiresCookiesSpec")
    @Refreshable
    static class JsonWebKeysProvider implements JwkProvider {
        private final List<JWK> jwks

        JsonWebKeysProvider(PrimarySignatureConfiguration primaryRsaPrivateKey) {
            jwks = Collections.singletonList(primaryRsaPrivateKey.getPublicJWK())
        }

        @Override
        List<JWK> retrieveJsonWebKeys() {
            return jwks
        }
    }
}
