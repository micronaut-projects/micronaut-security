package io.micronaut.security.oauth2.client

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.context.annotation.Value
import io.micronaut.core.annotation.Nullable
import io.micronaut.core.io.socket.SocketUtils
import io.micronaut.core.util.StringUtils
import io.micronaut.http.*
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Filter
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.ProxyHttpClient
import io.micronaut.http.filter.HttpServerFilter
import io.micronaut.http.filter.ServerFilterChain
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
import org.reactivestreams.Publisher
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import reactor.core.publisher.Mono
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll
import uk.org.webcompere.systemstubs.properties.SystemProperties

import java.security.Principal
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.concurrent.atomic.AtomicBoolean
import java.util.function.Function

class JwksUriSignatureProxySpec extends Specification {

    static final String SPEC_NAME_PROPERTY = 'spec.name'

    @Shared
    Map authConfig = [
            (SPEC_NAME_PROPERTY)                : 'jwks-uri-proxy.auth',
            'micronaut.server.port': SocketUtils.findAvailableTcpPort(),
            'micronaut.security.authentication' : 'bearer'
    ]

    @AutoCleanup
    @Shared
    EmbeddedServer authEmbeddedServer = ApplicationContext.run(EmbeddedServer, authConfig)

    HttpClient authClient = authEmbeddedServer.applicationContext.createBean(HttpClient, authEmbeddedServer.getURL())

    @Shared
    Map proxyConfig = [
            (SPEC_NAME_PROPERTY)    : 'jwks-uri-proxy.proxy',
            'forward-proxy-host'    : authEmbeddedServer.host,
            'forward-proxy-port'    : authEmbeddedServer.port
    ]

    @AutoCleanup
    @Shared
    EmbeddedServer proxyEmbeddedServer = ApplicationContext.run(EmbeddedServer, proxyConfig)

    def cleanup() {
        proxyEmbeddedServer.applicationContext.getBean(ProxyFilter.class).keySetProxied.set(false)
    }

    private static Function<Integer, SystemProperties> systemPropertiesFunction() {
        return new Function<Integer, SystemProperties>() {
            @Override
            SystemProperties apply(Integer port) {
                SystemProperties proxyProps = new SystemProperties()
                proxyProps.set("http.proxyHost", "localhost")
                proxyProps.set("http.proxyPort", port)
                proxyProps.set("http.nonProxyHosts", "")
                return proxyProps
            }
        }
    }

    @Unroll("#description")
    def "jwks key set loading"(String description, Map<String, Object> configuration, Function<Integer, SystemProperties> systemProperties) {
        given:
        EmbeddedServer globalClientEmbeddedServer = ApplicationContext.run(EmbeddedServer, configuration)
        EmbeddedServer clientServer = ApplicationContext.run(EmbeddedServer, [ (SPEC_NAME_PROPERTY) : 'jwks-uri-proxy.client' ])
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
        HttpRequest<?> request = HttpRequest.GET('/').bearerAuth(rsp.body().accessToken)
        String username = systemProperties != null ? systemProperties.apply(proxyEmbeddedServer.port).execute(() -> booksClient.toBlocking().retrieve(request, String))
                : booksClient.toBlocking().retrieve(request, String)

        then:
        username == 'user'
        filter.keySetProxied.get() == (systemProperties != null || globalClientEmbeddedServer.applicationContext.getProperty("micronaut.security.token.jwt.signatures.jwks-client.http-client.enabled", Boolean, true))

        cleanup:
        globalClientEmbeddedServer.close()
        clientServer.close()

        where:
        [description, configuration, systemProperties] << [
                [
                        "jwks key set loading with Nimbus library resource retriever client uses system properties proxy config",
                        [
                                (SPEC_NAME_PROPERTY)                                        : 'jwks-uri-proxy.books',
                                "micronaut.security.token.jwt.signatures.jwks-client.http-client.enabled": StringUtils.FALSE,
                                'micronaut.security.authentication': 'idtoken',
                                'micronaut.security.oauth2.clients.a.client-id': "XXX",
                                'micronaut.security.oauth2.clients.a.openid.issuer' : "http://localhost:${authEmbeddedServer.port}/oauth2/default"
                        ],
                        systemPropertiesFunction()
                ],
                [
                        "jwks key set loading with Nimbus library resource retriever client can be used without proxy config",
                        [
                                (SPEC_NAME_PROPERTY)                                        : 'jwks-uri-proxy.books',
                                "micronaut.security.token.jwt.signatures.jwks-client.http-client.enabled": StringUtils.FALSE,
                                'micronaut.security.authentication': 'idtoken',
                                'micronaut.security.oauth2.clients.a.client-id': "XXX",
                                'micronaut.security.oauth2.clients.a.openid.issuer' : "http://localhost:${authEmbeddedServer.port}/oauth2/default"
                        ],
                        null
                ],
                [
                        "jwks key set loading uses service level http client proxy config",
                        [
                                (SPEC_NAME_PROPERTY)                                        : 'jwks-uri-proxy.books',
                                'micronaut.http.services.a.url'                       : "http://localhost:${authEmbeddedServer.port}",
                                'micronaut.http.services.a.proxy-type'                : 'http',
                                'micronaut.http.services.a.proxy-address'             : "localhost:${proxyEmbeddedServer.port}",
                                'micronaut.security.authentication': 'idtoken',
                                'micronaut.security.oauth2.clients.a.client-id': "XXX",
                                'micronaut.security.oauth2.clients.a.openid.issuer' : "http://localhost:${authEmbeddedServer.port}/oauth2/default"
                        ],
                        null
                ],
                [
                        "jwks key set loading uses global http client proxy config",
                        [
                                    (SPEC_NAME_PROPERTY)                                        : 'jwks-uri-proxy.books',
                                    'micronaut.http.client.proxy-type'                          : 'http',
                                    'micronaut.http.client.proxy-address'                       : "localhost:${proxyEmbeddedServer.port}",
                                    'micronaut.security.authentication': 'idtoken',
                                    'micronaut.security.oauth2.clients.a.client-id': "XXX",
                                    'micronaut.security.oauth2.clients.a.openid.issuer' : "http://localhost:${authEmbeddedServer.port}/oauth2/default"
                        ],
                        null
                ]

        ]
    }

    @Requires(property = 'spec.name', value = 'jwks-uri-proxy.books')
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
    @Requires(property = 'spec.name', value = 'jwks-uri-proxy.proxy')
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
    @Requires(property = 'spec.name', value = 'jwks-uri-proxy.auth')
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario( 'user')])
        }
    }

    @Requires(property = 'spec.name', value = 'jwks-uri-proxy.auth')
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

    @Requires(property = 'spec.name', value = 'jwks-uri-proxy.auth')
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
    @Requires(property = 'spec.name', value = 'jwks-uri-proxy.auth')
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
