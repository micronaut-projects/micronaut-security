package io.micronaut.security.token.jwt.signature.jwks

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.SignedJWT
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
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
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureGeneratorConfiguration
import reactor.core.publisher.FluxSink
import reactor.core.publisher.Flux
import org.reactivestreams.Publisher
import spock.lang.Specification
import spock.util.concurrent.PollingConditions

import jakarta.inject.Named
import jakarta.inject.Singleton
import java.security.Principal
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

class NotAvailableRemoteJwksSpec extends Specification {

    void "start an app, validation fails if remote jwks down. If the jwks endpoint goes live validation works"() {
        given:
        int authServerPort = SocketUtils.findAvailableTcpPort()

        Map<String, Object> configuration =
            [
                    'spec.name': 'NotAvailableRemoteJwksSpec',
                    'micronaut.security.token.jwt.signatures.jwks.foo.url': "http://localhost:${authServerPort}/keys",
                    'micronaut.http.client.read-timeout': '5s',
            ]

        Map<String, Object> authServerConfiguration =
            [
                    'micronaut.server.port': authServerPort,
                    'spec.name': 'AuthServerNotAvailableRemoteJwksSpec',
                    'micronaut.security.authentication': 'bearer',
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
        authEmbeddedServer.close()
        authServerClient.close()
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
        authEmbeddedServer = ApplicationContext.run(EmbeddedServer, authServerConfiguration)
        authServerClient = authEmbeddedServer.applicationContext.createBean(HttpClient, authEmbeddedServer.URL).toBlocking()

        PollingConditions pollingConditions = new PollingConditions()

        then:
        pollingConditions.eventually {
            authServerClient.exchange(HttpRequest.GET('/keys')).status() == HttpStatus.OK
        }

        when: 'authentication should work since JWKS endpoint is up'
        HttpResponse<String> usernameRsp = client.exchange(HttpRequest.GET('/username').bearerAuth(jwt), String)

        then:
        noExceptionThrown()
        usernameRsp.status() == HttpStatus.OK
        usernameRsp.body() == 'sherlock'

        cleanup:
        embeddedServer.close()
        authEmbeddedServer.close()
        authServerClient.close()
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
        private static JWK jwk

        //storing this statically to use the same key across restarts
        static {
            jwk = new RSAKeyGenerator(2048)
                    .algorithm(JWSAlgorithm.RS256)
                    .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key
                    .keyID(UUID.randomUUID().toString()) // give the key a unique ID
                    .generate();
        }


        AuthServerJwkProvider() {
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

    @Requires(property = 'spec.name', value = 'AuthServerNotAvailableRemoteJwksSpec')
    @Singleton
    static class MockAuthenticationProvider implements AuthenticationProvider {
        @Override
        Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            Flux.create({emitter ->
                emitter.next(new UserDetails(authenticationRequest.identity as String, []))
                emitter.complete()
            }, FluxSink.OverflowStrategy.ERROR)
        }
    }

}
