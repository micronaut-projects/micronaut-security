package io.micronaut.security.oauth2.client

import com.fasterxml.jackson.databind.ObjectMapper
import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.SignedJWT
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.context.annotation.Value
import io.micronaut.core.io.socket.SocketUtils
import io.micronaut.http.HttpMethod
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.token.config.TokenConfiguration
import io.micronaut.security.token.jwt.endpoints.JwkProvider
import io.micronaut.security.token.jwt.endpoints.KeysController
import io.micronaut.security.token.jwt.render.AccessRefreshToken
import io.micronaut.security.token.jwt.signature.SignatureConfiguration
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureGeneratorConfiguration
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import io.reactivex.Single
import org.reactivestreams.Publisher
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import spock.lang.Specification
import spock.util.concurrent.PollingConditions

import javax.inject.Named
import javax.inject.Singleton
import java.security.Principal
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

class JwksUriSignatureSpec extends Specification {
    private static final Logger LOG = LoggerFactory.getLogger(JwksUriSignatureSpec.class)

    void "registering an open id client, creates a JwskUriSignature with the jws_uri exposed in the openid-configuration endpoint"() {
        given:
        int authServerAPort = SocketUtils.findAvailableTcpPort()
        int authServerBPort = SocketUtils.findAvailableTcpPort()

        when:
        Map<String, Object> authServerAConfig = [
                'micronaut.server.port': authServerAPort,
                'micronaut.security.authentication': 'bearer',
                'spec.name': 'AuthServerAJwksUriSignatureSpec']
        EmbeddedServer authServerA = ApplicationContext.run(EmbeddedServer, authServerAConfig)

        then:
        new PollingConditions().eventually {
            assert authServerA.isRunning()
        }

        when:
        Map<String, Object> authServerBConfig = [
                'micronaut.server.port': authServerBPort,
                'micronaut.security.authentication': 'bearer',
                'spec.name': 'AuthServerBJwksUriSignatureSpec']
        EmbeddedServer authServerB = ApplicationContext.run(EmbeddedServer, authServerBConfig)

        then:
        new PollingConditions().eventually {
            assert authServerB.isRunning()
        }

        when:
        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer,[
                'micronaut.security.authentication': 'idtoken',
                'micronaut.security.oauth2.clients.a.openid.issuer' : "http://localhost:${authServerAPort}/oauth2/default",
                'micronaut.security.oauth2.clients.b.openid.issuer' : "http://localhost:${authServerBPort}/oauth2/default",
                'spec.name'                                            : 'JwksUriSignatureSpec',
        ] as Map<String, Object>)

        then:
        new PollingConditions().eventually {
            assert embeddedServer.isRunning()
        }
        embeddedServer.applicationContext.containsBean(SignatureConfiguration)


        when: 'it is possible to get a JWT from the auth server A'
        BlockingHttpClient authServerAClient = authServerA.applicationContext.createBean(HttpClient, authServerA.URL).toBlocking()
        HttpResponse<AccessRefreshToken> accessRefreshTokenHttpResponse = authServerAClient.exchange(loginRequest(), AccessRefreshToken)

        then:
        noExceptionThrown()
        accessRefreshTokenHttpResponse.status == HttpStatus.OK
        accessRefreshTokenHttpResponse.body.isPresent()

        when: 'verify the retried access token is a signed JWT'
        String jwtA = accessRefreshTokenHttpResponse.body.get().accessToken

        then:
        jwtA
        JWTParser.parse(jwtA) instanceof SignedJWT

        when: 'it is possible to get a JWT from the auth server B'
        BlockingHttpClient authServerBClient = authServerA.applicationContext.createBean(HttpClient, authServerB.URL).toBlocking()
        accessRefreshTokenHttpResponse = authServerBClient.exchange(loginRequest(), AccessRefreshToken)

        then:
        noExceptionThrown()
        accessRefreshTokenHttpResponse.status == HttpStatus.OK
        accessRefreshTokenHttpResponse.body.isPresent()

        when: 'verify the retried access token is a signed JWT'
        String jwtB = accessRefreshTokenHttpResponse.body.get().accessToken

        then:
        jwtB
        JWTParser.parse(jwtB) instanceof SignedJWT

        and:'authorization servers are not contacted until the first request comes in'
        authServerA.applicationContext.getBean(AuthServerAOpenIdConfigurationController).invocations == 0
        authServerA.applicationContext.getBean(AuthServerAKeysController).invocations == 0
        authServerB.applicationContext.getBean(AuthServerBOpenIdConfigurationController).invocations == 0
        authServerB.applicationContext.getBean(AuthServerBKeysController).invocations == 0

        when: 'authentication should work since the auth server JWKS endpoint is configured automatically'
        BlockingHttpClient client = embeddedServer.applicationContext.createBean(HttpClient, embeddedServer.URL).toBlocking()
        HttpResponse<String> usernameRsp = client.exchange(HttpRequest.GET('/username').bearerAuth(jwtA), String)

        then:
        noExceptionThrown()
        usernameRsp.status() == HttpStatus.OK
        usernameRsp.body() == 'sherlock'

        when:
        usernameRsp = client.exchange(HttpRequest.GET('/username').bearerAuth(jwtB), String)

        then:
        noExceptionThrown()
        usernameRsp.status() == HttpStatus.OK
        usernameRsp.body() == 'sherlock'

        and:
        authServerA.applicationContext.getBean(AuthServerAOpenIdConfigurationController).invocations == 1
        authServerA.applicationContext.getBean(AuthServerAKeysController).invocations >= 1

        and:
        authServerB.applicationContext.getBean(AuthServerBOpenIdConfigurationController).invocations == 1
        authServerB.applicationContext.getBean(AuthServerBKeysController).invocations >= 1

        cleanup:
        authServerA.close()
        authServerB.close()
        embeddedServer.close()
    }

    @Requires(property = 'spec.name', value = 'JwksUriSignatureSpec')
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Controller("/username")
    static class EchoUsernameController {
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String index(Principal principal) {
            principal.name
        }
    }


    @Requires(property = 'spec.name', value = 'AuthServerAJwksUriSignatureSpec')
    @Controller("/oauth2/default/.well-known/openid-configuration")
    static class AuthServerAOpenIdConfigurationController {
        int invocations = 0
        Integer port
        AuthServerAOpenIdConfigurationController(@Value('${micronaut.server.port}') Integer port) {
            this.port = port
        }
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get
        String index() {
            invocations++
            OpenIdConfiguration.configuration(port)
        }
    }
    @Requires(property = 'spec.name', value = 'AuthServerBJwksUriSignatureSpec')
    @Controller("/oauth2/default/.well-known/openid-configuration")
    static class AuthServerBOpenIdConfigurationController {
        int invocations = 0
        Integer port
        AuthServerBOpenIdConfigurationController(@Value('${micronaut.server.port}') Integer port) {
            this.port = port
        }
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get
        String index() {
            invocations++
            OpenIdConfiguration.configuration(port)
        }
    }

    @Requires(property = 'spec.name', value = 'AuthServerBJwksUriSignatureSpec')
    @Named("generator")
    @Singleton
    static class AuthServerBJwkProvider implements JwkProvider, RSASignatureGeneratorConfiguration {
        JWK jwk

        AuthServerBJwkProvider() {
            this.jwk = JWKGenerator.generateJwk(JWSAlgorithm.RS256)
        }

        @Override
        List<JWK> retrieveJsonWebKeys() {
            [jwk.toPublicJWK()]
        }

        @Override
        RSAPublicKey getPublicKey() {
            (RSAPublicKey) ((RSAKey) jwk).toPublicKey()
        }

        @Override
        RSAPrivateKey getPrivateKey() {
            (RSAPrivateKey) ((RSAKey) jwk).toPrivateKey()
        }

        @Override
        JWSAlgorithm getJwsAlgorithm() {
            return JWSAlgorithm.RS256
        }
    }

    @Requires(property = 'spec.name', value = 'AuthServerAJwksUriSignatureSpec')
    @Named("generator")
    @Singleton
    static class AuthServerAJwkProvider implements JwkProvider, RSASignatureGeneratorConfiguration {
        JWK jwk

        AuthServerAJwkProvider() {
            this.jwk = JWKGenerator.generateJwk(JWSAlgorithm.RS256)
        }

        @Override
        List<JWK> retrieveJsonWebKeys() {
            [jwk.toPublicJWK()]
        }

        @Override
        RSAPublicKey getPublicKey() {
            (RSAPublicKey) ((RSAKey) jwk).toPublicKey()
        }

        @Override
        RSAPrivateKey getPrivateKey() {
            (RSAPrivateKey) ((RSAKey) jwk).toPrivateKey()
        }

        @Override
        JWSAlgorithm getJwsAlgorithm() {
            return JWSAlgorithm.RS256
        }
    }

    @Requires(property = 'spec.name', value = 'AuthServerBJwksUriSignatureSpec')
    @Replaces(KeysController)
    @Controller('/keys')
    @Secured(SecurityRule.IS_ANONYMOUS)
    static class AuthServerBKeysController extends KeysController {
        int invocations = 0

        AuthServerBKeysController(Collection<JwkProvider> jwkProviders, ObjectMapper objectMapper) {
            super(jwkProviders, objectMapper)
        }

        @Override
        @Get
        Single<String> keys() {
            invocations++
            return super.keys()
        }
    }

    @Requires(property = 'spec.name', value = 'AuthServerAJwksUriSignatureSpec')
    @Replaces(KeysController)
    @Controller('/keys')
    @Secured(SecurityRule.IS_ANONYMOUS)
    static class AuthServerAKeysController extends KeysController {
        int invocations = 0

        AuthServerAKeysController(Collection<JwkProvider> jwkProviders, ObjectMapper objectMapper) {
            super(jwkProviders, objectMapper)
        }

        @Override
        @Get
        Single<String> keys() {
            invocations++
            return super.keys()
        }
    }

    @Requires(property = 'spec.name', value = 'AuthServerAJwksUriSignatureSpec')
    @Singleton
    static class AuthServerAAuthenticationProvider implements AuthenticationProvider {

        @Override
        Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            Flowable.create({ emitter ->
                emitter.onNext(AuthenticationResponse.build(authenticationRequest.identity as String, new TokenConfiguration() {}))
                emitter.onComplete()
            }, BackpressureStrategy.ERROR)
        }
    }
    @Requires(property = 'spec.name', value = 'AuthServerBJwksUriSignatureSpec')
    @Singleton
    static class AuthServerBAuthenticationProvider implements AuthenticationProvider {

        @Override
        Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            Flowable.create( {emitter ->
                emitter.onNext(AuthenticationResponse.build(authenticationRequest.identity as String, new TokenConfiguration() {}))
                emitter.onComplete()
            }, BackpressureStrategy.ERROR)
        }
    }

    static class OpenIdConfiguration {
        static String configuration(Integer port) {
            '{"issuer":"https://dev-133320.okta.com/oauth2/default","authorization_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/authorize","token_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/token","userinfo_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/userinfo","registration_endpoint":"https://dev-133320.okta.com/oauth2/v1/clients","jwks_uri":"http://localhost:' + port + '/keys","response_types_supported":["code","id_token","code id_token","code token","id_token token","code id_token token"],"response_modes_supported":["query","fragment","form_post","okta_post_message"],"grant_types_supported":["authorization_code","implicit","refresh_token","password"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"scopes_supported":["openid","profile","email","address","phone","offline_access"],"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"claims_supported":["iss","ver","sub","aud","iat","exp","jti","auth_time","amr","idp","nonce","name","nickname","preferred_username","given_name","middle_name","family_name","email","email_verified","profile","zoneinfo","locale","address","phone_number","picture","website","gender","birthdate","updated_at","at_hash","c_hash"],"code_challenge_methods_supported":["S256"],"introspection_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/introspect","introspection_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"revocation_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/revoke","revocation_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"end_session_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/logout","request_parameter_supported":true,"request_object_signing_alg_values_supported":["HS256","HS384","HS512","RS256","RS384","RS512","ES256","ES384","ES512"]}'
        }
    }

    static class JWKGenerator {
        static JWK generateJwk(JWSAlgorithm alg) {
            try {
                return new RSAKeyGenerator(2048)
                        .algorithm(alg)
                        .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key
                        .keyID(UUID.randomUUID().toString()) // give the key a unique ID
                        .generate()
            } catch (JOSEException e) {
                if (LOG.isErrorEnabled()) {
                    LOG.error("error while generating a JWK");
                }
            }
            return null
        }
    }

    private HttpRequest loginRequest() {
        HttpRequest.create(HttpMethod.POST, '/login')
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .body(new UsernamePasswordCredentials('sherlock', 'elementary'))
    }
}
