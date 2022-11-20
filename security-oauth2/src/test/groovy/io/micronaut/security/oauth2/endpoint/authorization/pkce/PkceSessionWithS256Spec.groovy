package io.micronaut.security.oauth2.endpoint.authorization.pkce

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.context.exceptions.ConfigurationException
import io.micronaut.core.annotation.NonNull
import io.micronaut.core.annotation.Nullable
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
import io.micronaut.runtime.context.scope.Refreshable
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.handlers.RedirectingLoginHandler
import io.micronaut.security.oauth2.client.OauthClient
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse
import io.micronaut.security.oauth2.grants.AuthorizationCodeGrant
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.BrowserHttpRequest
import io.micronaut.security.token.jwt.endpoints.JwkProvider
import io.micronaut.security.token.jwt.generator.AccessRefreshTokenGenerator
import io.micronaut.security.token.jwt.generator.claims.JwtClaims
import io.micronaut.security.token.jwt.render.AccessRefreshToken
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureConfiguration
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureGeneratorConfiguration
import jakarta.inject.Named
import jakarta.inject.Singleton
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import spock.lang.Specification

import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.text.ParseException

import static com.nimbusds.jose.jwk.KeyUse.SIGNATURE

class PkceSessionWithS256Spec extends Specification {
    void "test PKCE with session persistence and a remote server supporting code challenge S256"() {
        given: 'create an auth server and server which uses OpenID connect auto-configuration pointint to the auth server'
        EmbeddedServer oauthServer = ApplicationContext.run(EmbeddedServer, [
            "spec.name": "AuthServerPkceSessionWithS256Spec",
            "micronaut.security.oauth2.pkce.enabled": StringUtils.TRUE,
            // Enable so that beans in this package (such as the beans in this test) io.micronaut.security.oauth2.endpoint.authorization.pkce are loaded
        ] as Map<String, Object>)

        EmbeddedServer server = ApplicationContext.run(EmbeddedServer, [
            "spec.name": "PkceSessionWithS256Spec",
            "micronaut.security.authentication": "session",
            "micronaut.security.oauth2.pkce.persistence": "session",
            'micronaut.http.client.followRedirects': false,
            "micronaut.security.oauth2.pkce.enabled": StringUtils.TRUE,
            "micronaut.security.oauth2.clients.auth.openid.issuer": "http://localhost:${oauthServer.port}/oauth2/default".toString(),
            "micronaut.security.oauth2.clients.auth.client-id": "xxx",
            "micronaut.security.oauth2.clients.auth.client-secret": "xxx",
            "micronaut.security.redirect.unauthorized.url": "/oauth/login/auth",
        ])
        and: 'create HTTP clients pointing to both the server and auth server'
        HttpClient httpClient = server.applicationContext.createBean(HttpClient, server.URL)
        BlockingHttpClient client = httpClient.toBlocking()
        HttpClient authServerHttpClient = oauthServer.applicationContext.createBean(HttpClient, oauthServer.URL)
        BlockingHttpClient authServerClient = authServerHttpClient.toBlocking()

        expect: 'the server contains necessary beans for OAuth 2'
        server
        server.applicationContext.containsBean(HomeController)
        server.applicationContext.containsBean(RedirectingLoginHandler)
        server.applicationContext.containsBean(OauthClient)

        and: 'auth server is exposing the AuthServerController routes'
        oauthServer
        oauthServer.applicationContext.containsBean(AuthServerController)

        when: 'auth server exposes keys endpoint and requires no authentication'
        HttpResponse<?> response = authServerClient.exchange(HttpRequest.GET("/keys"))

        then:
        noExceptionThrown()
        HttpStatus.OK == response.status()

        when: 'if you visit a secured endpoint you are redirected to /oauth/login/auth'
        HttpRequest<?> request = BrowserHttpRequest.GET("/secured")
        response = client.exchange(request)

        then:
        HttpStatus.SEE_OTHER == response.status()

        when:
        String location = response.getHeaders().get(HttpHeaders.LOCATION)

        then:
        '/oauth/login/auth' == location

        when: 'visiting the OAuth 2.0 login endpoint redirects to the auth server authorization endpoint and sets cookies for pkce state and nonce'
        response = client.exchange(location)

        then:
        HttpStatus.FOUND == response.status()

        when:
        location = response.getHeaders().get(HttpHeaders.LOCATION)
        Cookie cookieState = response.cookies.get("OAUTH2_STATE")
        Cookie cookieNonce = response.cookies.get("OPENID_NONCE")
        Cookie cookieSession = response.cookies.get("SESSION")
        client.exchange(HttpRequest.GET(location))

        then:
        oauthServer.applicationContext.getBean(AuthServerController).codeChallenge
        'S256' == oauthServer.applicationContext.getBean(AuthServerController).codeChallengeMethod
        oauthServer.applicationContext.getBean(AuthServerController).state
        !response.cookies.get("OAUTH2_PKCE")
        cookieState
        cookieNonce
        cookieSession

        when: 'if you emulate receiving a callback from the Auth server, the OAuth handshanke is done and the code verifier is sent'
        HttpRequest<?> callbackRequest = HttpRequest.POST("/oauth/callback/auth",
                CollectionUtils.mapOf("code", "xxx",
                        "state", oauthServer.applicationContext.getBean(AuthServerController).state))
                .cookie(cookieState)
                .cookie(cookieNonce)
                .cookie(cookieSession)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        response = client.exchange(callbackRequest)

        then:
        HttpStatus.SEE_OTHER == response.status()
        '/' == response.getHeaders().get(HttpHeaders.LOCATION)

        cleanup:
        server.close()
        oauthServer.close()
    }

    @Requires(property = "spec.name", value="PkceSessionWithS256Spec")
    @Controller
    static class HomeController {
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Status(HttpStatus.I_AM_A_TEAPOT)
        void index() {
        }

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Status(HttpStatus.ENHANCE_YOUR_CALM)
        @Get("/secured")
        void secured() {
        }
    }

    @Requires(property = "spec.name", value="AuthServerPkceSessionWithS256Spec")
    @Secured(SecurityRule.IS_ANONYMOUS)
    @Controller
    static class AuthServerController {
        private final HttpHostResolver httpHostResolver
        String codeChallenge
        String codeChallengeMethod
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
            codeChallengeMethod = request.getParameters().get("code_challenge_method")
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
                    CollectionUtils.mapOf(JwtClaims.ISSUER, host + "/oauth2/default",
                    JwtClaims.AUDIENCE, Collections.singletonList("xxx"),
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

    static abstract class AbstractRSASignatureConfiguration
            implements RSASignatureConfiguration {

        private static final Logger LOG = LoggerFactory.getLogger(AbstractRSASignatureConfiguration.class);

        protected final JWK publicJWK;
        protected final RSAPublicKey publicKey;
        protected final RSAPrivateKey privateKey;
        protected final JWSAlgorithm jwsAlgorithm;

        public AbstractRSASignatureConfiguration(String jsonJwk) {
            RSAKey primaryRSAKey = parseRSAKey(jsonJwk)
                    .orElseThrow(() -> new ConfigurationException("could not parse primary JWK to RSA Key"));

            publicJWK = primaryRSAKey.toPublicJWK();

            try {
                privateKey = primaryRSAKey.toRSAPrivateKey();
            } catch (JOSEException e) {
                throw new ConfigurationException("could not primary RSA private key");
            }

            try {
                publicKey = primaryRSAKey.toRSAPublicKey();
            } catch (JOSEException e) {
                throw new ConfigurationException("could not primary RSA public key");
            }

            jwsAlgorithm = parseJWSAlgorithm(primaryRSAKey)
                    .orElseThrow(() -> new ConfigurationException("could not parse JWS Algorithm from RSA Key"));
        }


        JWSAlgorithm getJwsAlgorithm() {
            return jwsAlgorithm
        }

        @NonNull
        JWK getPublicJWK() {
            return publicJWK;
        }

        @Override
        public RSAPublicKey getPublicKey() {
            return publicKey;
        }

        @NonNull
        private Optional<JWSAlgorithm> parseJWSAlgorithm(@NonNull RSAKey rsaKey) {
            Algorithm algorithm = rsaKey.getAlgorithm();
            if (algorithm == null) {
                return Optional.empty()
            }

            if (algorithm instanceof JWSAlgorithm) {
                return Optional.of((JWSAlgorithm) algorithm);
            }

            return Optional.of(JWSAlgorithm.parse(algorithm.getName()));
        }

        @NonNull
        private Optional<RSAKey> parseRSAKey(@NonNull String jsonJwk) {
            try {
                JWK jwk = JWK.parse(jsonJwk);
                if (!(jwk instanceof RSAKey)) {
                    LOG.warn("JWK is not an RSAKey");
                    return Optional.empty();
                }
                return Optional.of((RSAKey) jwk);
            } catch (ParseException e) {
                LOG.warn("Could not parse JWK JSON string {}", jsonJwk);
                return Optional.empty();
            }
        }

        RSAPrivateKey getPrivateKey() {
            return this.privateKey
        }
    }

    @Requires(property = "spec.name", value="AuthServerPkceSessionWithS256Spec")
    @Refreshable
    @Named("generator")
    static class PrimarySignatureConfiguration extends AbstractRSASignatureConfiguration implements RSASignatureGeneratorConfiguration {

        PrimarySignatureConfiguration(RS256JsonWebKeyGenerator generator) {
            super(generator.generateJsonWebKey());
        }
        @Override
        RSAPrivateKey getPrivateKey() {
            return super.getPrivateKey();
        }
        @Override
        JWSAlgorithm getJwsAlgorithm() {
            return super.getJwsAlgorithm();
        }
    }

    @Requires(property = "spec.name", value="AuthServerPkceSessionWithS256Spec")
    @Refreshable
    static class SecondarySignatureConfiguration extends AbstractRSASignatureConfiguration {
        SecondarySignatureConfiguration(RS256JsonWebKeyGenerator generator) {
            super(generator.generateJsonWebKey());
        }
    }

    @Requires(property = "spec.name", value="AuthServerPkceSessionWithS256Spec")
    @Singleton
    static class RS256JsonWebKeyGenerator {
        @NonNull
        String generateJsonWebKey(@Nullable String kid) throws JOSEException {
            return new RSAKeyGenerator(2048)
                    .algorithm(JWSAlgorithm.RS256)
                        .keyUse(SIGNATURE)
                        .keyID(kid != null ? kid : generateKid()) // give the key a unique ID
                        .generate()
                        .toJSONString()
        }
        @NonNull
        String generateJsonWebKey() throws JOSEException {
            generateJsonWebKey(generateKid());
        }
        private static String generateKid() {
            return UUID.randomUUID().toString().replaceAll("-", "");
        }
    }

    @Requires(property = "spec.name", value="AuthServerPkceSessionWithS256Spec")
    @Refreshable
    static class JsonWebKeysProvider implements JwkProvider {
        private final List<JWK> jwks;
        JsonWebKeysProvider(PrimarySignatureConfiguration primaryRsaPrivateKey,
                            SecondarySignatureConfiguration secondarySignatureConfiguration) {
            jwks = Arrays.asList(primaryRsaPrivateKey.getPublicJWK(), secondarySignatureConfiguration.getPublicJWK());
        }
        @Override
        List<JWK> retrieveJsonWebKeys() {
            return jwks;
        }
    }
}
