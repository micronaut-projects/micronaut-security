package io.micronaut.security.oauth2.endpoint.authorization.state

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
import io.micronaut.http.uri.UriBuilder
import io.micronaut.runtime.context.scope.Refreshable
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.oauth2.endpoint.authorization.pkce.S256PkceGenerator
import io.micronaut.security.oauth2.endpoint.authorization.state.persistence.StateKeyedSessionValues
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse
import io.micronaut.security.oauth2.grants.AuthorizationCodeGrant
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.BrowserHttpRequest
import io.micronaut.security.token.Claims
import io.micronaut.security.token.jwt.endpoints.JwkProvider
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureConfiguration
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureGeneratorConfiguration
import io.micronaut.security.token.render.AccessRefreshToken
import io.micronaut.security.token.generator.AccessRefreshTokenGenerator
import jakarta.inject.Named
import jakarta.inject.Singleton
import org.jspecify.annotations.NonNull
import org.jspecify.annotations.Nullable
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import spock.lang.Specification

import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.text.ParseException
import java.util.concurrent.ConcurrentHashMap

import static com.nimbusds.jose.jwk.KeyUse.SIGNATURE

/**
 * Verifies that, with session persistence for state, PKCE and nonce, several OAuth 2.0 login flows can be in flight
 * in the same HTTP session (for example, two browser tabs) and each can be completed with its own state, code verifier
 * and nonce.
 */
class ConcurrentSessionLoginFlowsSpec extends Specification {

    private static final String LOGIN_FAILURE = '/login-failed'

    EmbeddedServer oauthServer
    EmbeddedServer server
    BlockingHttpClient client

    void setup() {
        oauthServer = ApplicationContext.run(EmbeddedServer, [
            "spec.name": "AuthServerConcurrentSessionLoginFlowsSpec",
        ] as Map<String, Object>)
        server = ApplicationContext.run(EmbeddedServer, [
            "spec.name": "ConcurrentSessionLoginFlowsSpec",
            "micronaut.security.authentication": "session",
            "micronaut.security.oauth2.state.persistence": "session",
            "micronaut.security.oauth2.pkce.persistence": "session",
            "micronaut.security.oauth2.openid.nonce.persistence": "session",
            'micronaut.http.client.followRedirects': false,
            "micronaut.security.oauth2.clients.auth.openid.issuer": "http://localhost:${oauthServer.port}/oauth2/default".toString(),
            "micronaut.security.oauth2.clients.auth.client-id": "xxx",
            "micronaut.security.oauth2.clients.auth.client-secret": "xxx",
            "micronaut.security.redirect.unauthorized.url": "/oauth/login/auth",
            "micronaut.security.redirect.login-failure": LOGIN_FAILURE,
        ])
        client = server.applicationContext.createBean(HttpClient, server.URL).toBlocking()
    }

    void cleanup() {
        server.close()
        oauthServer.close()
    }

    void "two login flows started in the same session can both be completed, oldest first"() {
        when: 'a first login flow is started; it creates the session'
        HttpResponse<?> response = client.exchange(BrowserHttpRequest.GET('/oauth/login/auth'))
        Cookie sessionCookie = response.cookies.get('SESSION')

        then:
        HttpStatus.FOUND == response.status()
        sessionCookie
        !response.cookies.get('OAUTH2_STATE')
        !response.cookies.get('OAUTH2_PKCE')
        !response.cookies.get('OPENID_NONCE')

        when: 'the browser follows the redirect to the authorization server'
        String firstState = startFlow(response)

        and: 'a second login flow is started in the same session'
        String secondState = startFlow(client.exchange(BrowserHttpRequest.GET('/oauth/login/auth').cookie(sessionCookie)))

        then:
        firstState != secondState
        authServer.flows.keySet() == [firstState, secondState] as Set

        when: 'the first flow is completed with its own state (and the code verifier and nonce of the first flow)'
        response = client.exchange(callback(firstState, sessionCookie))

        then:
        HttpStatus.SEE_OTHER == response.status()
        '/' == response.getHeaders().get(HttpHeaders.LOCATION)
        authServer.exchangedStates == [firstState]

        when: 'the second flow is completed with its own state'
        response = client.exchange(callback(secondState, sessionCookie))

        then:
        HttpStatus.SEE_OTHER == response.status()
        '/' == response.getHeaders().get(HttpHeaders.LOCATION)
        authServer.exchangedStates == [firstState, secondState]

        when: 'a state cannot be reused once consumed'
        response = client.exchange(callback(firstState, sessionCookie))

        then:
        HttpStatus.SEE_OTHER == response.status()
        LOGIN_FAILURE == response.getHeaders().get(HttpHeaders.LOCATION)
    }

    void "two login flows started in the same session can both be completed, newest first"() {
        when:
        HttpResponse<?> response = client.exchange(BrowserHttpRequest.GET('/oauth/login/auth'))
        Cookie sessionCookie = response.cookies.get('SESSION')
        String firstState = startFlow(response)
        String secondState = startFlow(client.exchange(BrowserHttpRequest.GET('/oauth/login/auth').cookie(sessionCookie)))

        and:
        response = client.exchange(callback(secondState, sessionCookie))

        then:
        HttpStatus.SEE_OTHER == response.status()
        '/' == response.getHeaders().get(HttpHeaders.LOCATION)

        when:
        response = client.exchange(callback(firstState, sessionCookie))

        then:
        HttpStatus.SEE_OTHER == response.status()
        '/' == response.getHeaders().get(HttpHeaders.LOCATION)
        authServer.exchangedStates == [secondState, firstState]
    }

    void "starting more login flows than the bound evicts the oldest flow"() {
        when:
        HttpResponse<?> response = client.exchange(BrowserHttpRequest.GET('/oauth/login/auth'))
        Cookie sessionCookie = response.cookies.get('SESSION')
        List<String> states = [startFlow(response)]
        StateKeyedSessionValues.MAX_ENTRIES.times {
            states << startFlow(client.exchange(BrowserHttpRequest.GET('/oauth/login/auth').cookie(sessionCookie)))
        }

        then:
        states.size() == StateKeyedSessionValues.MAX_ENTRIES + 1

        when: 'the oldest flow was evicted, so its callback fails'
        response = client.exchange(callback(states.first(), sessionCookie))

        then:
        HttpStatus.SEE_OTHER == response.status()
        LOGIN_FAILURE == response.getHeaders().get(HttpHeaders.LOCATION)
        authServer.exchangedStates.isEmpty()

        when: 'the remaining flows can all be completed'
        List<String> locations = states.drop(1).collect {
            client.exchange(callback(it, sessionCookie)).getHeaders().get(HttpHeaders.LOCATION)
        }

        then:
        locations.every { it == '/' }
        authServer.exchangedStates == states.drop(1)
    }

    private AuthServerController getAuthServer() {
        oauthServer.applicationContext.getBean(AuthServerController)
    }

    /**
     * Follows the redirect to the authorization server so that it records the parameters of the flow.
     * @return the state parameter of the flow
     */
    private String startFlow(HttpResponse<?> loginResponse) {
        assert HttpStatus.FOUND == loginResponse.status()
        String location = loginResponse.getHeaders().get(HttpHeaders.LOCATION)
        client.exchange(HttpRequest.GET(location))
        String state = UriBuilder.of(location).build().query.split('&').find { it.startsWith('state=') }?.substring('state='.length())
        assert state
        assert authServer.flows.containsKey(state)
        state
    }

    /**
     * Emulates the callback from the authorization server. The authorization code is the state, so that the fake
     * authorization server can verify the code verifier against the challenge of that flow and return its nonce.
     */
    private static HttpRequest<?> callback(String state, Cookie sessionCookie) {
        HttpRequest.POST("/oauth/callback/auth", CollectionUtils.mapOf("code", state, "state", state))
                .cookie(sessionCookie)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
    }

    @Requires(property = "spec.name", value = "ConcurrentSessionLoginFlowsSpec")
    @Controller
    static class HomeController {
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Status(HttpStatus.I_AM_A_TEAPOT)
        void index() {
        }
    }

    static class Flow {
        String codeChallenge
        String codeChallengeMethod
        String nonce
    }

    @Requires(property = "spec.name", value = "AuthServerConcurrentSessionLoginFlowsSpec")
    @Secured(SecurityRule.IS_ANONYMOUS)
    @Controller
    static class AuthServerController {
        private final HttpHostResolver httpHostResolver
        private final AccessRefreshTokenGenerator accessRefreshTokenGenerator
        final Map<String, Flow> flows = new ConcurrentHashMap<>()
        final List<String> exchangedStates = Collections.synchronizedList([])

        AuthServerController(HttpHostResolver httpHostResolver, AccessRefreshTokenGenerator accessRefreshTokenGenerator) {
            this.httpHostResolver = httpHostResolver
            this.accessRefreshTokenGenerator = accessRefreshTokenGenerator
        }

        @Consumes(MediaType.TEXT_HTML)
        @Get("/oauth2/default/v1/authorize")
        @Status(HttpStatus.OK)
        void authorized(HttpRequest<?> request) {
            Flow flow = new Flow()
            flow.codeChallenge = request.getParameters().get("code_challenge")
            flow.codeChallengeMethod = request.getParameters().get("code_challenge_method")
            flow.nonce = request.getParameters().get("nonce")
            flows.put(request.getParameters().get("state"), flow)
        }

        @Produces(MediaType.APPLICATION_JSON)
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Post("/oauth2/default/v1/token")
        @Status(HttpStatus.OK)
        HttpResponse<?> token(HttpRequest<?> request, @Body AuthorizationCodeGrant codeGrant) {
            String host = httpHostResolver.resolve(request)
            Flow flow = flows.get(codeGrant.getCode())
            if (flow == null) {
                return HttpResponse.unprocessableEntity()
            }
            String codeVerifier = codeGrant.getCodeVerifier()
            if (StringUtils.isEmpty(codeVerifier)) {
                return HttpResponse.unprocessableEntity()
            }
            if (flow.codeChallengeMethod != 'S256' || !S256PkceGenerator.hash(codeVerifier).equals(flow.codeChallenge)) {
                return HttpResponse.unprocessableEntity()
            }
            exchangedStates << codeGrant.getCode()
            AccessRefreshToken accessRefreshToken = accessRefreshTokenGenerator.generate(Authentication.build("john", Collections.emptyList(),
                    CollectionUtils.mapOf(Claims.ISSUER, host + "/oauth2/default",
                            Claims.AUDIENCE, Collections.singletonList("xxx"),
                            OpenIdClaims.CLAIMS_NONCE, flow.nonce))).get()
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
        private Optional<JWSAlgorithm> parseJWSAlgorithm(@NonNull RSAKey rsaKey) {
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
        private Optional<RSAKey> parseRSAKey(@NonNull String jsonJwk) {
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

    @Requires(property = "spec.name", value = "AuthServerConcurrentSessionLoginFlowsSpec")
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

    @Requires(property = "spec.name", value = "AuthServerConcurrentSessionLoginFlowsSpec")
    @Singleton
    static class RS256JsonWebKeyGenerator {
        @NonNull
        String generateJsonWebKey(@Nullable String kid) throws JOSEException {
            return new RSAKeyGenerator(2048)
                    .algorithm(JWSAlgorithm.RS256)
                    .keyUse(SIGNATURE)
                    .keyID(kid != null ? kid : generateKid())
                    .generate()
                    .toJSONString()
        }

        @NonNull
        String generateJsonWebKey() throws JOSEException {
            generateJsonWebKey(generateKid())
        }

        private static String generateKid() {
            return UUID.randomUUID().toString().replaceAll("-", "")
        }
    }

    @Requires(property = "spec.name", value = "AuthServerConcurrentSessionLoginFlowsSpec")
    @Refreshable
    static class JsonWebKeysProvider implements JwkProvider {
        private final List<JWK> jwks

        JsonWebKeysProvider(PrimarySignatureConfiguration primaryRsaPrivateKey) {
            jwks = [primaryRsaPrivateKey.getPublicJWK()]
        }

        @Override
        List<JWK> retrieveJsonWebKeys() {
            return jwks
        }
    }
}
