package io.micronaut.security.oauth2.client

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.context.annotation.Value
import io.micronaut.core.annotation.Nullable
import io.micronaut.core.io.socket.SocketUtils
import io.micronaut.http.*
import io.micronaut.http.annotation.Consumes
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Header
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.retry.annotation.Retryable
import io.micronaut.runtime.ApplicationConfiguration
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import io.micronaut.security.token.claims.ClaimsAudienceProvider
import io.micronaut.security.token.claims.JtiGenerator
import io.micronaut.security.token.config.TokenConfiguration
import io.micronaut.security.token.jwt.endpoints.JwkProvider
import io.micronaut.security.token.jwt.generator.claims.JWTClaimsSetGenerator
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureGeneratorConfiguration
import io.micronaut.security.token.render.BearerAccessRefreshToken
import jakarta.inject.Named
import jakarta.inject.Singleton
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import spock.lang.Specification

import java.security.Principal
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.concurrent.atomic.AtomicInteger

class JwksUriSignatureTimeoutSpec extends Specification {

    static final String SPEC_NAME_PROPERTY = 'spec.name'

    def "authorization does not fail when loading JWKS with limited thread resources"() {
        given:
        EmbeddedServer authEmbeddedServer = ApplicationContext.run(EmbeddedServer, [
                (SPEC_NAME_PROPERTY)                : 'JwksUriSignatureTimeoutSpec.auth',
                'retry-jwks' : false,
                'micronaut.server.port': SocketUtils.findAvailableTcpPort(),
                'micronaut.security.authentication' : 'bearer'
        ])
        EmbeddedServer echoEmbeddedServer = ApplicationContext.run(EmbeddedServer, [
                (SPEC_NAME_PROPERTY)                                        : 'JwksUriSignatureTimeoutSpec.books',
                'micronaut.netty.event-loops.default.num-threads': 1,
                'micronaut.http.client.read-timeout': '1s',
                'micronaut.security.authentication': 'idtoken',
                'micronaut.security.oauth2.clients.a.client-id': "XXX",
                'micronaut.security.oauth2.clients.a.openid.issuer' : "http://localhost:${authEmbeddedServer.port}/oauth2/default"
        ])
        EmbeddedServer clientServer = ApplicationContext.run(EmbeddedServer, [
                (SPEC_NAME_PROPERTY) : 'JwksUriSignatureTimeoutSpec.client',
                'books-server.url' : echoEmbeddedServer.getURL()
        ])

        HttpClient authClient = authEmbeddedServer.applicationContext.createBean(HttpClient, authEmbeddedServer.getURL())
        EchoClient echoClient = clientServer.applicationContext.createBean(EchoClient)

        when:
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials('user', 'password')
        HttpResponse rsp = authClient.toBlocking().exchange(HttpRequest.POST('/login', creds), BearerAccessRefreshToken)

        then:
        rsp.status() == HttpStatus.OK
        rsp.body().accessToken
        !rsp.body().refreshToken

        when:
        String result = echoClient.getUserName(HttpHeaderValues.AUTHORIZATION_PREFIX_BEARER + " " + rsp.body().accessToken)

        then:
        result == "user"

        cleanup:
        authEmbeddedServer.close()
        echoEmbeddedServer.close()
        clientServer.close()
    }

    def "authorization can use configured retry when loading JWKS with limited thread resources"() {
        given:
        EmbeddedServer authEmbeddedServer = ApplicationContext.run(EmbeddedServer, [
                (SPEC_NAME_PROPERTY)                : 'JwksUriSignatureTimeoutSpec.auth',
                'retry-jwks' : true,
                'micronaut.server.port': SocketUtils.findAvailableTcpPort(),
                'micronaut.security.authentication' : 'bearer'
        ])
        EmbeddedServer echoEmbeddedServer = ApplicationContext.run(EmbeddedServer, [
                (SPEC_NAME_PROPERTY)                                        : 'JwksUriSignatureTimeoutSpec.books',
                'micronaut.netty.event-loops.default.num-threads': 1,
                'micronaut.http.client.read-timeout': '1s',
                'micronaut.security.authentication': 'idtoken',
                'micronaut.security.oauth2.clients.a.client-id': "XXX",
                'micronaut.security.oauth2.clients.a.openid.issuer' : "http://localhost:${authEmbeddedServer.port}/oauth2/default"
        ])
        EmbeddedServer clientServer = ApplicationContext.run(EmbeddedServer, [
                (SPEC_NAME_PROPERTY) : 'JwksUriSignatureTimeoutSpec.client-retry',
                'books-server.url' : echoEmbeddedServer.getURL()
        ])

        HttpClient authClient = authEmbeddedServer.applicationContext.createBean(HttpClient, authEmbeddedServer.getURL())
        RetryableEchoClient echoClient = clientServer.applicationContext.createBean(RetryableEchoClient)

        when:
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials('user', 'password')
        HttpResponse rsp = authClient.toBlocking().exchange(HttpRequest.POST('/login', creds), BearerAccessRefreshToken)

        then:
        rsp.status() == HttpStatus.OK
        rsp.body().accessToken
        !rsp.body().refreshToken

        when:
        String result = echoClient.getUserName(HttpHeaderValues.AUTHORIZATION_PREFIX_BEARER + " " + rsp.body().accessToken)

        then:
        result == "user"

        cleanup:
        authEmbeddedServer.close()
        echoEmbeddedServer.close()
        clientServer.close()
    }

    @Requires(property = 'spec.name', value = 'JwksUriSignatureTimeoutSpec.client')
    @Client('${books-server.url}')
    static interface EchoClient {
        @Consumes(MediaType.TEXT_PLAIN)
        @Get("/user")
        String getUserName(@Header(HttpHeaders.AUTHORIZATION) String bearerToken)
    }

    @Requires(property = 'spec.name', value = 'JwksUriSignatureTimeoutSpec.client-retry')
    @Client('${books-server.url}')
    @Retryable(attempts = '2')
    static interface RetryableEchoClient {
        @Consumes(MediaType.TEXT_PLAIN)
        @Get("/user")
        String getUserName(@Header(HttpHeaders.AUTHORIZATION) String bearerToken)
    }

    @Requires(property = 'spec.name', value = 'JwksUriSignatureTimeoutSpec.books')
    @Controller("/user")
    @Secured(SecurityRule.IS_AUTHENTICATED)
    static class EchoController {

        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String username(Principal principal) {
            principal.name
        }
    }

    @Singleton
    @Requires(property = 'spec.name', value = 'JwksUriSignatureTimeoutSpec.auth')
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario( 'user')])
        }
    }

    @Requires(property = 'spec.name', value = 'JwksUriSignatureTimeoutSpec.auth')
    @Replaces(JWTClaimsSetGenerator)
    @Singleton
    static class AuthServerACustomJWTClaimsSetGenerator extends JWTClaimsSetGenerator {
        Integer port
        AuthServerACustomJWTClaimsSetGenerator(TokenConfiguration tokenConfiguration,
                                               @Nullable JtiGenerator jwtIdGenerator,
                                               @Nullable ClaimsAudienceProvider claimsAudienceProvider,
                                               @Nullable ApplicationConfiguration applicationConfiguration,
                                               @Value('${micronaut.server.port}') Integer port) {
            super(tokenConfiguration, jwtIdGenerator, claimsAudienceProvider, applicationConfiguration)
            this.port = port
        }

        @Override
        protected void populateIss(JWTClaimsSet.Builder builder) {
            builder.issuer("http://localhost:${port}/oauth2/default")
        }

        @Override
        protected void populateAud(JWTClaimsSet.Builder builder) {
            builder.audience("XXX")
        }
    }

    @Requires(property = 'spec.name', value = 'JwksUriSignatureTimeoutSpec.auth')
    @Controller("/oauth2/default/.well-known/openid-configuration")
    static class AuthServerOpenIdConfigurationController {
        Integer port
        AuthServerOpenIdConfigurationController(@Value('${micronaut.server.port}') Integer port) {
            this.port = port
        }
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get
        String index() {
            '{"issuer":"http://localhost:' + port + '/oauth2/default","authorization_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/authorize","token_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/token","userinfo_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/userinfo","registration_endpoint":"https://dev-133320.okta.com/oauth2/v1/clients","jwks_uri":"http://localhost:' + port + '/keys","response_types_supported":["code","id_token","code id_token","code token","id_token token","code id_token token"],"response_modes_supported":["query","fragment","form_post","okta_post_message"],"grant_types_supported":["authorization_code","implicit","refresh_token","password"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"scopes_supported":["openid","profile","email","address","phone","offline_access"],"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"claims_supported":["iss","ver","sub","aud","iat","exp","jti","auth_time","amr","idp","nonce","name","nickname","preferred_username","given_name","middle_name","family_name","email","email_verified","profile","zoneinfo","locale","address","phone_number","picture","website","gender","birthdate","updated_at","at_hash","c_hash"],"code_challenge_methods_supported":["S256"],"introspection_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/introspect","introspection_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"revocation_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/revoke","revocation_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"],"end_session_endpoint":"https://dev-133320.okta.com/oauth2/default/v1/logout","request_parameter_supported":true,"request_object_signing_alg_values_supported":["HS256","HS384","HS512","RS256","RS384","RS512","ES256","ES384","ES512"]}'
        }
    }

    @Named("generator")
    @Singleton
    @Requires(property = 'spec.name', value = 'JwksUriSignatureTimeoutSpec.auth')
    static class SlowJwkProvider implements JwkProvider, RSASignatureGeneratorConfiguration {

        private RSAKey jwk

        private boolean initialized = false

        //@Inject
        @Property(name = 'retry-jwks')
        boolean isRetry

        private AtomicInteger keyRequestCount = new AtomicInteger(0)

        private static final Logger LOG = LoggerFactory.getLogger(SlowJwkProvider.class)

        SlowJwkProvider() {
            String keyId = UUID.randomUUID().toString()
            try {
                this.jwk = new RSAKeyGenerator(2048)
                        .algorithm(JWSAlgorithm.RS256)
                        .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key
                        .keyID(keyId) // give the key a unique ID
                        .generate()

            } catch (JOSEException e) {

            }
        }

        @Override
        List<JWK> retrieveJsonWebKeys() {
            if (initialized && isRetry) {
                if (keyRequestCount.incrementAndGet() < 3) {
                    Thread.sleep(6000)
                }
            } else {
                initialized = true
            }
            [jwk]
        }

        @Override
        RSAPrivateKey getPrivateKey() {
            try {
                return jwk.toRSAPrivateKey()
            } catch (JOSEException e) {
                if (LOG.isErrorEnabled()) {
                    LOG.error("JOSEException getting RSA private key", e)
                }
            }
            return null
        }

        @Override
        JWSAlgorithm getJwsAlgorithm() {
            if (jwk.getAlgorithm() instanceof JWSAlgorithm) {
                return (JWSAlgorithm) jwk.getAlgorithm()
            }
            return null
        }

        @Override
        RSAPublicKey getPublicKey() {
            try {
                return jwk.toRSAPublicKey()
            } catch (JOSEException e) {
                if (LOG.isErrorEnabled()) {
                    LOG.error("JOSEException getting RSA public key", e)
                }
            }
            return null
        }
    }
}
