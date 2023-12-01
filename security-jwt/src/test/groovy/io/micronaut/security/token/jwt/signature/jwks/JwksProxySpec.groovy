package io.micronaut.security.token.jwt.signature.jwks

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Factory
import io.micronaut.context.annotation.Primary
import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.context.annotation.Value
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpMethod
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.MutableHttpResponse
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Filter
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.ProxyHttpClient
import io.micronaut.http.filter.HttpServerFilter
import io.micronaut.http.filter.ServerFilterChain
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import io.micronaut.security.token.jwt.endpoints.JwkProvider
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureGeneratorConfiguration
import io.micronaut.security.token.render.BearerAccessRefreshToken
import jakarta.inject.Named
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import reactor.core.publisher.Mono
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification
import uk.org.webcompere.systemstubs.properties.SystemProperties

import java.security.Principal
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.concurrent.atomic.AtomicBoolean

class JwksProxySpec extends Specification {

    static final String SPEC_NAME_PROPERTY = 'spec.name'

    @Shared
    Map authConfig = [
            (SPEC_NAME_PROPERTY)                : 'jwks-proxy.auth',
            'micronaut.security.authentication' : 'bearer'
    ]

    @AutoCleanup
    @Shared
    EmbeddedServer authEmbeddedServer = ApplicationContext.run(EmbeddedServer, authConfig)

    HttpClient authClient = authEmbeddedServer.applicationContext.createBean(HttpClient, authEmbeddedServer.getURL())

    @Shared
    Map proxyConfig = [
            (SPEC_NAME_PROPERTY)    : 'jwks-proxy.proxy',
            'forward-proxy-host'    : authEmbeddedServer.host,
            'forward-proxy-port'    : authEmbeddedServer.port
    ]

    @AutoCleanup
    @Shared
    EmbeddedServer proxyEmbeddedServer = ApplicationContext.run(EmbeddedServer, proxyConfig)

    def cleanup() {
        proxyEmbeddedServer.applicationContext.getBean(ProxyFilter.class).keySetProxied.set(false)
    }

    def "jwks key set loading uses global http client proxy config"() {
        given:
        EmbeddedServer globalClientEmbeddedServer = ApplicationContext.run(EmbeddedServer, [
                (SPEC_NAME_PROPERTY)                                        : 'jwks-proxy.books',
                'micronaut.http.client.proxy-type'                          : 'http',
                'micronaut.http.client.proxy-address'                       : "localhost:${proxyEmbeddedServer.port}",
                'micronaut.security.token.jwt.signatures.jwks.gateway.url'  : "http://localhost:${authEmbeddedServer.port}/keys",
        ])
        ApplicationContext clientContext = ApplicationContext.run([ (SPEC_NAME_PROPERTY) : 'jwks-proxy.client' ])
        HttpClient booksClient = clientContext.createBean(HttpClient, globalClientEmbeddedServer.getURL())
        ProxyFilter filter = proxyEmbeddedServer.applicationContext.getBean(ProxyFilter.class)

        when:
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials('user', 'password')
        HttpResponse rsp = authClient.toBlocking().exchange(HttpRequest.POST('/login', creds), BearerAccessRefreshToken)

        then:
        rsp.status() == HttpStatus.OK
        rsp.body().accessToken
        !rsp.body().refreshToken

        when:
        String username = booksClient.toBlocking().retrieve(HttpRequest.GET('/').bearerAuth(rsp.body().accessToken), String)

        then:
        username == 'user'
        filter.keySetProxied.get()

        cleanup:
        globalClientEmbeddedServer.close()
        clientContext.close()
    }

    def "jwks key set loading uses service level http client proxy config"() {
        given:
        EmbeddedServer globalClientEmbeddedServer = ApplicationContext.run(EmbeddedServer, [
                (SPEC_NAME_PROPERTY)                                        : 'jwks-proxy.books',
                'micronaut.http.services.gateway.url'                       : "http://localhost:${authEmbeddedServer.port}",
                'micronaut.http.services.gateway.proxy-type'                : 'http',
                'micronaut.http.services.gateway.proxy-address'             : "localhost:${proxyEmbeddedServer.port}",
                'micronaut.security.token.jwt.signatures.jwks.gateway.url'  : "/keys",
        ])
        ApplicationContext clientContext = ApplicationContext.run([ (SPEC_NAME_PROPERTY) : 'jwks-proxy.client' ])
        HttpClient booksClient = clientContext.createBean(HttpClient, globalClientEmbeddedServer.getURL())
        ProxyFilter filter = proxyEmbeddedServer.applicationContext.getBean(ProxyFilter.class)

        when:
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials('user', 'password')
        HttpResponse rsp = authClient.toBlocking().exchange(HttpRequest.POST('/login', creds), BearerAccessRefreshToken)

        then:
        rsp.status() == HttpStatus.OK
        rsp.body().accessToken
        !rsp.body().refreshToken

        when:
        String username = booksClient.toBlocking().retrieve(HttpRequest.GET('/').bearerAuth(rsp.body().accessToken), String)

        then:
        username == 'user'
        filter.keySetProxied.get()

        cleanup:
        globalClientEmbeddedServer.close()
        clientContext.close()
    }

    def "jwks key set loading with Nimbus library resource retriever client uses system properties proxy config"() {
        given:
        SystemProperties proxyProps = new SystemProperties()
        proxyProps.set("http.proxyHost", "localhost")
        proxyProps.set("http.proxyPort", "${proxyEmbeddedServer.port}")
        proxyProps.set("http.nonProxyHosts", "")

        EmbeddedServer globalClientEmbeddedServer = ApplicationContext.run(EmbeddedServer, [
                (SPEC_NAME_PROPERTY)                                        : 'jwks-proxy.books',
                'spec.replace-client'                                       : true,
                'micronaut.security.token.jwt.signatures.jwks.gateway.url'  : "http://localhost:${authEmbeddedServer.port}/keys",
        ])
        EmbeddedServer clientServer = ApplicationContext.run(EmbeddedServer, [ (SPEC_NAME_PROPERTY) : 'jwks-proxy.client' ])
        HttpClient booksClient = clientServer.applicationContext.createBean(HttpClient, globalClientEmbeddedServer.getURL())

        ProxyFilter filter = proxyEmbeddedServer.applicationContext.getBean(ProxyFilter.class)

        when:
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials('user', 'password')
        HttpResponse rsp = authClient.toBlocking().exchange(HttpRequest.POST('/login', creds), BearerAccessRefreshToken)

        then:
        rsp.status() == HttpStatus.OK
        rsp.body().accessToken
        !rsp.body().refreshToken

        when:
        String username = proxyProps.execute(() -> {
            return booksClient.toBlocking().retrieve(HttpRequest.GET('/').bearerAuth(rsp.body().accessToken), String)
        })

        then:
        username == 'user'
        filter.keySetProxied.get()

        cleanup:
        globalClientEmbeddedServer.close()
        clientServer.close()
    }

    def "jwks key set loading with Nimbus library resource retriever client can be used without proxy config"() {
        given:
        EmbeddedServer globalClientEmbeddedServer = ApplicationContext.run(EmbeddedServer, [
                (SPEC_NAME_PROPERTY)                                        : 'jwks-proxy.books',
                'spec.replace-client'                                       : true,
                'micronaut.security.token.jwt.signatures.jwks.gateway.url'  : "http://localhost:${authEmbeddedServer.port}/keys",
        ])
        EmbeddedServer clientServer = ApplicationContext.run(EmbeddedServer, [ (SPEC_NAME_PROPERTY) : 'jwks-proxy.client' ])
        HttpClient booksClient = clientServer.applicationContext.createBean(HttpClient, globalClientEmbeddedServer.getURL())

        ProxyFilter filter = proxyEmbeddedServer.applicationContext.getBean(ProxyFilter.class)

        when:
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials('user', 'password')
        HttpResponse rsp = authClient.toBlocking().exchange(HttpRequest.POST('/login', creds), BearerAccessRefreshToken)

        then:
        rsp.status() == HttpStatus.OK
        rsp.body().accessToken
        !rsp.body().refreshToken

        when:
        String username = booksClient.toBlocking().retrieve(HttpRequest.GET('/').bearerAuth(rsp.body().accessToken), String)

        then:
        username == 'user'
        !filter.keySetProxied.get()

        cleanup:
        globalClientEmbeddedServer.close()
        clientServer.close()
    }

    @Factory
    @Requires(property = 'spec.name', value = 'jwks-proxy.books')
    static class JwksClientFactory {

        @Replaces(HttpClientJwksClient.class)
        @Singleton
        @Primary
        @Requires(property = 'spec.replace-client', value = 'true')
        ResourceRetrieverJwksClient jwksClient(@Value('${spec.name}') String specName) {
            return new ResourceRetrieverJwksClient()
        }
    }

    @Singleton
    @Requires(property = 'spec.name', value = 'jwks-proxy.books')
    @Controller
    @Secured(SecurityRule.IS_AUTHENTICATED)
    static class HomeController {

        @Produces(MediaType.TEXT_HTML)
        @Get
        String username(Principal principal) {
            principal.name
        }
    }

    @Filter("/**")
    @Requires(property = 'spec.name', value = 'jwks-proxy.proxy')
    static class ProxyFilter implements HttpServerFilter {
        private final ProxyHttpClient client
        private final String targetHost
        private final int targetPort
        private AtomicBoolean keySetProxied = new AtomicBoolean(false);

        ProxyFilter(ProxyHttpClient client, @Value('${forward-proxy-host}') String targetHost, @Value('${forward-proxy-port}') int targetPort) {
            this.client = client
            this.targetHost = targetHost
            this.targetPort = targetPort
        }

        @Override
        Publisher<MutableHttpResponse<?>> doFilter(HttpRequest<?> request,
                                                          ServerFilterChain chain) {
            if (request.method == HttpMethod.CONNECT) {
                return Mono.just(HttpResponse.ok())
            }

            def forwardRequest = request.mutate()
                    .uri(b -> b
                            .scheme("http")
                            .host(targetHost)
                            .port(targetPort)
                    )
                    .header(HttpHeaders.VIA, "Micronaut")

            if ("/keys" == forwardRequest.getPath()) {
                keySetProxied.set(true)
            }

            return client.proxy(forwardRequest)
        }
    }

    @Singleton
    @Requires(property = 'spec.name', value = 'jwks-proxy.auth')
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario( 'user')])
        }
    }

    @Named("generator")
    @Singleton
    @Requires(property = 'spec.name', value = 'jwks-proxy.auth')
    static class RSAJwkProvider implements JwkProvider, RSASignatureGeneratorConfiguration {
        private RSAKey jwk

        private static final Logger LOG = LoggerFactory.getLogger(RSAJwkProvider.class)

        RSAJwkProvider() {

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
