package io.micronaut.security.oauth2.endpoint.token.response.validation

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.JWKGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.SignedJWT
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.core.util.StringUtils
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.http.server.util.HttpHostResolver
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.token.generator.TokenGenerator
import io.micronaut.security.token.jwt.endpoints.JwkProvider
import io.micronaut.security.token.jwt.generator.AccessTokenConfiguration
import io.micronaut.security.token.jwt.generator.claims.ClaimsGenerator
import io.micronaut.security.token.jwt.generator.claims.JwtClaims
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureGeneratorConfiguration
import jakarta.inject.Named
import jakarta.inject.Singleton
import spock.lang.Specification

import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

class AudienceClaimMatchesClientIdSpec extends Specification {

    void "test same issuer two different client ids"() {
        given:
        EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer, [
                "micronaut.security.reject-not-found": StringUtils.FALSE,
                "spec.name": "AudienceClaimMatchesClientIdSpecAuthServer"
        ])
        Map<String, Object> configuration = [
                "micronaut.security.authentication": "idtoken",
                "micronaut.security.reject-not-found": StringUtils.FALSE,
                "spec.name": "AudienceClaimMatchesClientIdSpec",
                "micronaut.security.oauth2.clients.auth.client-id": "AAA",
                "micronaut.security.oauth2.clients.auth.client-secret": "YYY",
                'micronaut.security.oauth2.clients.auth.openid.issuer': "http://localhost:${authServer.port}/oauth2/default"]
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer, configuration)
        HttpClient authServerHttpClient = server.applicationContext.createBean(HttpClient, authServer.URL)
        BlockingHttpClient authServerClient = authServerHttpClient.toBlocking()

        when:
        String keys = authServerClient.retrieve(HttpRequest.GET("/keys"))

        then:
        noExceptionThrown()
        keys != '{"keys":[]}'

        when:
        String clientAToken = authServerClient.retrieve(HttpRequest.GET("/token/clientA").accept(MediaType.TEXT_PLAIN))
        JWT clientAJWT = JWTParser.parse(clientAToken)

        then:
        clientAJWT instanceof SignedJWT
        clientAJWT.getJWTClaimsSet().getClaim("aud") == ["AAA"]
        clientAJWT.getJWTClaimsSet().getClaim("iss") == "http://localhost:${authServer.port}/oauth2/default"

        when:
        HttpClient httpClient = server.applicationContext.createBean(HttpClient, server.URL)
        BlockingHttpClient client = httpClient.toBlocking()
        client.retrieve(HttpRequest.GET("/hello").bearerAuth(clientAToken))

        then:
        noExceptionThrown()

        when:
        String clientBToken = authServerClient.retrieve(HttpRequest.GET("/token/clientB").accept(MediaType.TEXT_PLAIN))
        JWT clientBJWT = JWTParser.parse(clientBToken)

        then:
        clientBJWT instanceof SignedJWT
        clientBJWT.getJWTClaimsSet().getClaim("aud") == ["BBB"]
        clientBJWT.getJWTClaimsSet().getClaim("iss") == "http://localhost:${authServer.port}/oauth2/default"

        when:
        client.retrieve(HttpRequest.GET("/hello").bearerAuth(clientBToken))

        then:
        HttpClientResponseException e = thrown()
        HttpStatus.UNAUTHORIZED == e.status

        cleanup:
        authServerClient.close()
        authServerHttpClient.close()
        httpClient.close()
        client.close()
        server.close()
        authServer.close()
    }

    @Requires(property = 'spec.name', value = 'AudienceClaimMatchesClientIdSpec')
    @Controller("/hello")
    static class HelloWorldController {
        @Get
        @Secured(SecurityRule.IS_AUTHENTICATED)
        Map<String, String> index() {
            [message: 'Hello World']
        }
    }

    @Requires(property = "spec.name", value="AudienceClaimMatchesClientIdSpecAuthServer")
    @Secured(SecurityRule.IS_ANONYMOUS)
    @Controller
    static class AuthServerController {

        private final HttpHostResolver httpHostResolver
        private final TokenGenerator tokenGenerator
        private final AccessTokenConfiguration accessTokenConfiguration
        private final ClaimsGenerator claimsGenerator

        AuthServerController(HttpHostResolver httpHostResolver,
                             TokenGenerator tokenGenerator,
                             AccessTokenConfiguration accessTokenConfiguration,
                             ClaimsGenerator claimsGenerator) {
            this.httpHostResolver = httpHostResolver
            this.tokenGenerator = tokenGenerator
            this.accessTokenConfiguration = accessTokenConfiguration
            this.claimsGenerator = claimsGenerator
        }

        @Produces(MediaType.TEXT_PLAIN)
        @Get("/token/clientA")
        HttpResponse<Object> clientA(HttpRequest<?> request) {
            generateToken(request, "AAA")
        }

        @Produces(MediaType.TEXT_PLAIN)
        @Get("/token/clientB")
        HttpResponse<Object> clientB(HttpRequest<?> request) {
            generateToken(request, "BBB")
        }

        private HttpResponse<Object> generateToken(HttpRequest<?> request, String clientId) {
            String host = httpHostResolver.resolve(request)
            Map<String, Object> claims = new HashMap<>(claimsGenerator.generateClaims(Authentication.build("sherlock"), accessTokenConfiguration.expiration))
            claims[JwtClaims.ISSUER] = "${host}/oauth2/default".toString()
            claims[JwtClaims.AUDIENCE] = clientId
            tokenGenerator.generateToken(claims).map(HttpResponse::ok).orElseGet(() -> HttpResponse.serverError())
        }

        @Get("/oauth2/default/.well-known/openid-configuration")
        String openIdConfiguration(HttpRequest<?> request) {
            String host = httpHostResolver.resolve(request)
            '{"issuer":"' + host + '/oauth2/default","authorization_endpoint":"' + host + '/oauth2/default/v1/authorize","token_endpoint":"' + host + '/oauth2/default/v1/token","userinfo_endpoint":"' + host + '/oauth2/default/v1/userinfo","registration_endpoint":"' + host + '/oauth2/v1/clients","jwks_uri":"' + host + '/keys","response_types_supported":["code","id_token","code id_token","code token","id_token token","code id_token token"],"response_modes_supported":["query","fragment","form_post","okta_post_message"],"grant_types_supported":["authorization_code","implicit","refresh_token","password"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"scopes_supported":["openid","profile","email","address","phone","offline_access"],"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"claims_supported":["iss","ver","sub","aud","iat","exp","jti","auth_time","amr","idp","nonce","name","nickname","preferred_username","given_name","middle_name","family_name","email","email_verified","profile","zoneinfo","locale","address","phone_number","picture","website","gender","birthdate","updated_at","at_hash","c_hash"],"code_challenge_methods_supported":["S256"],"introspection_endpoint":"' + host + '/oauth2/default/v1/introspect","introspection_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"revocation_endpoint":"' + host + '/oauth2/default/v1/revoke","revocation_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"end_session_endpoint":"' + host + '/oauth2/default/v1/logout","request_parameter_supported":true,"request_object_signing_alg_values_supported":["HS256","HS384","HS512","RS256","RS384","RS512","ES256","ES384","ES512"]}'
        }
    }

    @Requires(property = 'spec.name', value = 'AudienceClaimMatchesClientIdSpecAuthServer')
    @Named("generator")
    @Singleton
    static class AuthServerSignatureConfiguration implements RSASignatureGeneratorConfiguration, JwkProvider {
        private final static JWSAlgorithm ALG = JWSAlgorithm.RS256
        private List<JWK> jwks = null
        private RSAKey rsaKey = null

        List<JWK> getJwks() {
            if (jwks == null) {
                this.jwks = Collections.singletonList(getRsaKey().toPublicJWK())
            }
            return jwks
        }

        RSAKey getRsaKey() {
            if (rsaKey == null) {
                JWKGenerator jwkGenerator = new RSAKeyGenerator(2048)
                        .algorithm(ALG)
                        .keyUse(KeyUse.SIGNATURE)
                this.rsaKey = jwkGenerator.generate()
            }
            return rsaKey
        }

        @Override
        RSAPublicKey getPublicKey() {
            getRsaKey().toRSAPublicKey()
        }

        @Override
        RSAPrivateKey getPrivateKey() {
            getRsaKey().toRSAPrivateKey()
        }

        @Override
        JWSAlgorithm getJwsAlgorithm() {
            ALG
        }

        @Override
        List<JWK> retrieveJsonWebKeys() {
            getJwks()
        }
    }
}
