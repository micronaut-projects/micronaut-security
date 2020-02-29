package io.micronaut.security.token.jwt.signature.jwks

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.SignedJWT
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.context.exceptions.ConfigurationException
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
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.token.jwt.endpoints.JwkProvider
import io.micronaut.security.token.jwt.render.AccessRefreshToken
import io.micronaut.security.token.jwt.signature.SignatureConfiguration
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureConfiguration
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureGeneratorConfiguration
import io.micronaut.security.token.views.UserDetailsEmail
import io.reactivex.Flowable
import org.reactivestreams.Publisher
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import spock.lang.Retry
import spock.lang.Shared
import spock.lang.Specification

import javax.inject.Named
import javax.inject.Singleton
import java.security.Principal
import java.security.PublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

class NotAvailableRemoteJwksSpec extends Specification {

    private static final Logger LOG = LoggerFactory.getLogger(NotAvailableRemoteJwksSpec.class)

    @Retry
    void "start an app, validation fails if remote jwks down. If the jwks endpoint goes live validation works"() {
        given:
        int authServerPort = SocketUtils.findAvailableTcpPort()

        Map<String, Object> configuration =
            [
                    'spec.name': 'NotAvailableRemoteJwksSpec',
                    'micronaut.security.token.jwt.signatures.jwks.foo.url': "http://localhost:${authServerPort}/keys",
                    'micronaut.http.client.read-timeout': '1s',
            ]


        Map<String, Object> authServerConfiguration =
            [
                    'micronaut.server.port': authServerPort,
                    'spec.name': 'AuthServerNotAvailableRemoteJwksSpec',
                    'micronaut.security.endpoints.login.enabled': true,
                    'micronaut.security.endpoints.keys.enabled': true,
            ]


        when: 'start auth server and expose an endpoint with JKWS'
        EmbeddedServer authEmbeddedServer = ApplicationContext.run(EmbeddedServer, authServerConfiguration)
        BlockingHttpClient authServerClient = authEmbeddedServer.applicationContext.createBean(HttpClient, authEmbeddedServer.URL).toBlocking()
        HttpResponse rsp = authServerClient.exchange(HttpRequest.GET('/keys'))

        then:
        noExceptionThrown()
        rsp.status() == HttpStatus.OK

        when: 'it is possible to get a JWT from the auth server'
        HttpResponse<AccessRefreshToken> accessRefreshTokenHttpResponse = authServerClient.exchange(HttpRequest.create(HttpMethod.POST, '/login')
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .body(new UsernamePasswordCredentials('sherlock', 'elementary')), AccessRefreshToken)

        then:
        noExceptionThrown()
        accessRefreshTokenHttpResponse.status.code == 200
        accessRefreshTokenHttpResponse.body.isPresent()

        when: 'verify the retried access token is a signed JWT'
        String jwt = accessRefreshTokenHttpResponse.body.get().accessToken

        then:
        jwt
        JWTParser.parse(jwt) instanceof SignedJWT

        when: 'Stop auth server, start server which uses the remote JWKS (Json Web Key Set) exposed by the auth server'
        authEmbeddedServer.stop()
        EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, configuration)

        then:
        embeddedServer.applicationContext.containsBean(SignatureConfiguration)

        when: 'authentication fails since JWKS endpoint is down'
        BlockingHttpClient client = embeddedServer.applicationContext.createBean(HttpClient, embeddedServer.URL).toBlocking()
        client.exchange(HttpRequest.GET('/username').bearerAuth(jwt), String)

        then:
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.UNAUTHORIZED

        when: 'start auth server'
        authEmbeddedServer.start()
        authServerClient.exchange(HttpRequest.GET('/keys'))

        then:
        noExceptionThrown()
        rsp.status() == HttpStatus.OK

        when: 'authentication should work since JWKS endpoint is up'
        HttpResponse<String> usernameRsp = client.exchange(HttpRequest.GET('/username').bearerAuth(jwt), String)

        then:
        noExceptionThrown()
        usernameRsp.status() == HttpStatus.OK
        usernameRsp.body() == 'sherlock'

        cleanup:
        embeddedServer.close()
        authEmbeddedServer.close()
    }

    @Requires(property = 'spec.name', value = 'NotAvailableRemoteJwksSpec')
    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Controller("/username")
    static class EchoUsernameController {

        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String index(Principal principal) {
            principal.name
        }

    }

    @Named("generator")
    @Requires(property = 'spec.name', value = 'AuthServerNotAvailableRemoteJwksSpec')
    @Singleton
    static class AuthServerJwkProvider implements JwkProvider, RSASignatureGeneratorConfiguration {
        JWK jwk

        AuthServerJwkProvider() {
            this.jwk = generateJwk()
        }

        @Override
        List<JWK> retrieveJsonWebKeys() {
            [jwk.toPublicJWK()]
        }

        JWK generateJwk() {
            try {
                return new RSAKeyGenerator(2048)
                        .algorithm(jwsAlgorithm)
                        .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key
                        .keyID(UUID.randomUUID().toString()) // give the key a unique ID
                        .generate();
            } catch (JOSEException e) {
                if (LOG.isErrorEnabled()) {
                    LOG.error("error while generating a JWK");
                }
            }
            return null
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

    @Requires(property = 'spec.name', value = 'AuthServerNotAvailableRemoteJwksSpec')
    @Singleton
    static class MockAuthenticationProvider implements AuthenticationProvider {
        @Override
        Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            Flowable.just(new UserDetails(authenticationRequest.identity as String, []))
        }
    }

}
