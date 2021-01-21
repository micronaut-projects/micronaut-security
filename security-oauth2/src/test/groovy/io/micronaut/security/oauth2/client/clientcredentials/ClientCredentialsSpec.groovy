package io.micronaut.security.oauth2.client.clientcredentials

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
import edu.umd.cs.findbugs.annotations.NonNull
import edu.umd.cs.findbugs.annotations.Nullable
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.ConfigurationProperties
import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Requires
import io.micronaut.context.exceptions.ConfigurationException
import io.micronaut.core.io.socket.SocketUtils
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Consumes
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Header
import io.micronaut.http.annotation.Post
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.BasicAuthUtils
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration
import io.micronaut.security.oauth2.endpoint.AuthenticationMethod
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse
import io.micronaut.security.oauth2.grants.ClientCredentialsGrant
import io.micronaut.security.oauth2.grants.GrantType
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.token.jwt.endpoints.JwkProvider
import io.micronaut.security.token.jwt.generator.AccessTokenConfiguration
import io.micronaut.security.token.jwt.generator.JwtTokenGenerator
import io.micronaut.security.token.jwt.generator.claims.JwtIdGenerator
import io.micronaut.security.token.jwt.signature.rsa.RSASignatureGeneratorConfiguration
import io.reactivex.Flowable
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import spock.lang.AutoCleanup
import spock.lang.Narrative
import spock.lang.Shared
import spock.lang.Specification

import javax.inject.Named
import javax.inject.Singleton
import javax.validation.constraints.NotBlank
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.text.ParseException

@Narrative('''
     +---------+                                  +---------------+
     |         |                                  |               |
     |         |>--(A)- Client Authentication --->| Authorization |
     | Client  |                                  |     Server    |
     |         |<--(B)---- Access Token ---------<|               |
     |         |                                  |               |
     +---------+                                  +---------------+
     
     +---------+                                  +-----------------+
     |         |                                  |                 |
     |         |>--(C)- Bearer Access Token ----->| Resource Server |
     | Client  |                                  |     Server      |
     |         |                                  |                 |
     |         |<--(D)---- Protected Resource ---<|                 |     
     +---------+                                  +-----------------+
''')
class ClientCredentialsSpec extends Specification {

    @Shared
    int authServerPort = SocketUtils.findAvailableTcpPort()

    @Shared
    int resourceServerPort = SocketUtils.findAvailableTcpPort()

    @Shared
    int authServerDownPort = SocketUtils.findAvailableTcpPort()

    @Shared
    @AutoCleanup
    EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer, [
            'spec.name'                                                     : 'ClientCredentialsSpecAuthServer',
            'micronaut.security.token.jwt.generator.access-token.expiration': 5,
            'authserver.config.jwk'                                         : jwkJsonString(),
            'micronaut.server.port'                                         : authServerPort,
            'sample.client-id'                                              : '3ljrgej68ggm7i720o9u12t7lm',
            'sample.client-secret'                                          : '1lk7on551mctn5gc78d1742at53l3npo3m375q0hcvr9t3eehgcf'
    ])

    @Shared
    @AutoCleanup
    EmbeddedServer authServerDown = ApplicationContext.run(EmbeddedServer, [
            'spec.name'                                                     : 'ClientCredentialsSpecAuthServerDown',
            'micronaut.security.token.jwt.generator.access-token.expiration': 5,
            'authserver.config.jwk'                                         : secondaryJwkJsonString,
            'micronaut.server.port'                                         : authServerDownPort,
    ])

    @Shared
    @AutoCleanup
    ApplicationContext authServerApplicationContext = authServer.applicationContext

    @Shared
    @AutoCleanup
    HttpClient authServerHttpClient = authServerApplicationContext.createBean(HttpClient, authServer.URL)

    @AutoCleanup
    @Shared
    BlockingHttpClient authServerClient = authServerHttpClient.toBlocking()

    @Shared
    @AutoCleanup
    EmbeddedServer resourceServer = ApplicationContext.run(EmbeddedServer, [
            'spec.name'                                                  : 'ClientCredentialsSpecResourceServer',
            'micronaut.security.token.jwt.signatures.jwks.authserver.url': "http://localhost:${authServerPort}/keys".toString(),
            'micronaut.security.intercept-url-map'                       : [[pattern: '/father', ('http-method'): 'GET', 'access': ['isAuthenticated()']]],
            'micronaut.server.port'                                      : resourceServerPort,
    ])

    @Shared
    ApplicationContext resourceServerApplicationContext = resourceServer.applicationContext

    @Shared
    @AutoCleanup
    HttpClient resourceServerHttpClient = resourceServerApplicationContext.createBean(HttpClient, resourceServer.URL)

    @AutoCleanup
    @Shared
    BlockingHttpClient resourceServerClient = resourceServerHttpClient.toBlocking()

    @Shared
    @AutoCleanup
    ApplicationContext applicationContext = ApplicationContext.run([
            'spec.name'                                                                                                         : 'ClientCredentialsSpec',
            'micronaut.security.oauth2.clients.authserveropenid.openid.issuer'                                                  : "http://localhost:$authServerPort".toString(),
            'micronaut.security.oauth2.clients.authserveropenid.client-id'                                                      : '3ljrgej68ggm7i720o9u12t7lm',
            'micronaut.security.oauth2.clients.authserveropenid.client-secret'                                                  : '1lk7on551mctn5gc78d1742at53l3npo3m375q0hcvr9t3eehgcf',
            'micronaut.security.oauth2.clients.authserveropenid.client-credentials.advanced-expiration'                         : '1s',

            'micronaut.security.oauth2.clients.authservermanual.token.auth-method'                                              : "client_secret_basic",
            'micronaut.security.oauth2.clients.authservermanual.token.url'                                                      : "http://localhost:$authServerPort/token".toString(),
            'micronaut.security.oauth2.clients.authservermanual.client-id'                                                      : '3ljrgej68ggm7i720o9u12t7lm',
            'micronaut.security.oauth2.clients.authservermanual.client-secret'                                                  : '1lk7on551mctn5gc78d1742at53l3npo3m375q0hcvr9t3eehgcf',
            'micronaut.security.oauth2.clients.authservermanual.client-credentials.service-id-regex'                            : 'resourceclient',
            'micronaut.security.oauth2.clients.authservermanual.client-credentials.advanced-expiration'                         : '1s',

            'micronaut.security.oauth2.clients.authservermanualtakesprecedenceoveropenid.openid.issuer'                         : "http://localhost:$authServerDownPort".toString(),
            'micronaut.security.oauth2.clients.authservermanualtakesprecedenceoveropenid.openid.token.auth-method'                     : "client_secret_basic",
            'micronaut.security.oauth2.clients.authservermanualtakesprecedenceoveropenid.openid.token.url'                             : "http://localhost:$authServerPort/token".toString(),
            'micronaut.security.oauth2.clients.authservermanualtakesprecedenceoveropenid.client-id'                             : '3ljrgej68ggm7i720o9u12t7lm',
            'micronaut.security.oauth2.clients.authservermanualtakesprecedenceoveropenid.client-secret'                         : '1lk7on551mctn5gc78d1742at53l3npo3m375q0hcvr9t3eehgcf',
            'micronaut.security.oauth2.clients.authservermanualtakesprecedenceoveropenid.client-credentials.advanced-expiration': '1s',
            'micronaut.http.services.resourceclient.url'                                                                        : "http://localhost:$resourceServerPort".toString(),
    ])

    void "verify tests is wired correctly"() {
        expect:
        authServerApplicationContext.containsBean(SampleClientConfiguration)
        authServerApplicationContext.containsBean(CustomJwkConfiguration)
        authServerApplicationContext.containsBean(MdxAuthRSASignatureConfiguration)
        authServerApplicationContext.containsBean(TokenController)
        !applicationContext.containsBean(SampleClientConfiguration)
        !resourceServerApplicationContext.containsBean(SampleClientConfiguration)
        !applicationContext.containsBean(TokenController)
        !resourceServerApplicationContext.containsBean(TokenController)
        !resourceServerApplicationContext.containsBean(MdxAuthRSASignatureConfiguration)
        !applicationContext.containsBean(MdxAuthRSASignatureConfiguration)
        !resourceServerApplicationContext.containsBean(CustomJwkConfiguration)
        !applicationContext.containsBean(CustomJwkConfiguration)
    }

    void 'auth server exposes openid-configuration endpoint'() {
        when:
        HttpResponse<Map> openIdConfigurationRsp = authServerClient.exchange(HttpRequest.GET("/.well-known/openid-configuration"), Map)

        then:
        openIdConfigurationRsp.status() == HttpStatus.OK
    }

    void "a bean of type OpenIdClientConfiguration is created for auth server"() {
        when :
        OpenIdClientConfiguration openIdClientConfiguration = applicationContext.getBean(OpenIdClientConfiguration, Qualifiers.byName('authserveropenid'))

        then:

        noExceptionThrown()
        openIdClientConfiguration.issuer.isPresent()
    }

    void 'auth server exposes key endpoint'() {
        when:
        HttpRequest request = HttpRequest.GET('/keys')
        HttpResponse<Map> rsp = authServerClient.exchange(request, Map)

        then:
        rsp.status() == HttpStatus.OK

    }

    void 'resource server endpoint is secured'() {
        when:
        HttpRequest<?> resourceServerRequest = HttpRequest.GET('/father').accept(MediaType.TEXT_PLAIN)
        resourceServerClient.exchange(resourceServerRequest)

        then:
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.UNAUTHORIZED
    }

    void 'you can access the resource server endpoint with a token generated by the auth server'() {
        when:
        JwtTokenGenerator jwtTokenGenerator = authServerApplicationContext.getBean(JwtTokenGenerator)
        Optional<String> jwtOptional =jwtTokenGenerator.generateToken(["sub": "john"])

        then:
        jwtOptional.isPresent()

        when:
        String jwt = jwtOptional.get()
        HttpRequest<?> resourceServerRequest = HttpRequest.GET('/father').accept(MediaType.TEXT_PLAIN).bearerAuth(jwt)
        HttpResponse<String> resourceServerResp = resourceServerClient.exchange(resourceServerRequest, String)

        then:
        resourceServerResp.status() == HttpStatus.OK
        resourceServerResp.getBody(String).isPresent()
        resourceServerResp.getBody(String).get() == "Your father is Rhaegar Targaryen"
    }

    void 'A manual token request with client credentials grant can be made, the access token obtained can access the resource server'() {
        when:
        OauthClientConfiguration oauthClientConfiguration = applicationContext.getBean(OauthClientConfiguration, Qualifiers.byName('authserveropenid'))
        SampleClientConfiguration sampleClientConfiguration = authServerApplicationContext.getBean(SampleClientConfiguration)

        then:
        oauthClientConfiguration.clientId == sampleClientConfiguration.clientId
        oauthClientConfiguration.clientSecret == sampleClientConfiguration.clientSecret

        when:
        HttpRequest<?> tokenRequest = HttpRequest.POST('/token', new ClientCredentialsGrant().toMap())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .basicAuth(oauthClientConfiguration.clientId, oauthClientConfiguration.clientSecret)
        HttpResponse<TokenResponse> httpTokenResponse = authServerClient.exchange(tokenRequest, TokenResponse)

        then:
        noExceptionThrown()
        httpTokenResponse.getBody(TokenResponse).isPresent()

        when:
        String accessToken = httpTokenResponse.getBody(TokenResponse).get().getAccessToken()
        HttpRequest<?> resourceServerRequest = HttpRequest.GET('/father').accept(MediaType.TEXT_PLAIN).bearerAuth(accessToken)
        HttpResponse<String> resourceServerResp = resourceServerClient.exchange(resourceServerRequest, String)

        then:
        resourceServerResp.status() == HttpStatus.OK
        resourceServerResp.getBody(String).isPresent()
        resourceServerResp.getBody(String).get() == "Your father is Rhaegar Targaryen"
    }

    void 'A bean of type ClientCredentialsClient is created for an OAuth 2.0 client which sets its token endpoint manually'() {

        when:
        ClientCredentialsClient clientCredentialsClient = applicationContext.getBean(ClientCredentialsClient, Qualifiers.byName("authservermanual"))

        then:
        noExceptionThrown()
        clientCredentialsClient.name == 'authservermanual'

        when:
        TokenResponse tokenResponse = Flowable.fromPublisher(clientCredentialsClient.requestToken()).blockingFirst()

        then:
        noExceptionThrown()

        when:
        String accessToken = tokenResponse.accessToken
        HttpRequest<?> resourceServerRequest = HttpRequest.GET('/father').accept(MediaType.TEXT_PLAIN).bearerAuth(accessToken)
        HttpResponse<String> resourceServerResp = resourceServerClient.exchange(resourceServerRequest, String)

        then:
        noExceptionThrown()
        resourceServerResp.status() == HttpStatus.OK
        resourceServerResp.getBody(String).isPresent()
        resourceServerResp.getBody(String).get() == "Your father is Rhaegar Targaryen"
    }

    void 'A bean of type ClientCredentialsClient is created for an OAuth 2.0 client which sets both token manually and an open id issuer which providers information about its token endpoint. The manual set token endpoint takes precedence'() {

        when:
        ClientCredentialsClient clientCredentialsClient = applicationContext.getBean(ClientCredentialsClient, Qualifiers.byName("authservermanualtakesprecedenceoveropenid"))

        then:
        noExceptionThrown()
        clientCredentialsClient instanceof DefaultClientCredentialsOpenIdClient
        clientCredentialsClient.name == 'authservermanualtakesprecedenceoveropenid'

        when:
        TokenResponse tokenResponse = Flowable.fromPublisher(clientCredentialsClient.requestToken()).blockingFirst()

        then:
        noExceptionThrown()

        when:
        String accessToken = tokenResponse.accessToken
        HttpRequest<?> resourceServerRequest = HttpRequest.GET('/father').accept(MediaType.TEXT_PLAIN).bearerAuth(accessToken)
        HttpResponse<String> resourceServerResp = resourceServerClient.exchange(resourceServerRequest, String)

        then:
        noExceptionThrown()
        resourceServerResp.status() == HttpStatus.OK
        resourceServerResp.getBody(String).isPresent()
        resourceServerResp.getBody(String).get() == "Your father is Rhaegar Targaryen"
    }

    void 'A bean of type ClientCredentialsClient is created for an OAuth 2.0 client which sets an open id issuer which providers information about its token endpoint'() {

        when:
        ClientCredentialsClient clientCredentialsClient = applicationContext.getBean(ClientCredentialsClient, Qualifiers.byName("authserveropenid"))

        then:
        noExceptionThrown()

        when:
        TokenResponse tokenResponse = Flowable.fromPublisher(clientCredentialsClient.requestToken()).blockingFirst()

        then:
        noExceptionThrown()

        when:
        String accessToken = tokenResponse.accessToken
        HttpRequest<?> resourceServerRequest = HttpRequest.GET('/father').accept(MediaType.TEXT_PLAIN).bearerAuth(accessToken)
        HttpResponse<String> resourceServerResp = resourceServerClient.exchange(resourceServerRequest, String)

        then:
        noExceptionThrown()
        resourceServerResp.status() == HttpStatus.OK
        resourceServerResp.getBody(String).isPresent()
        resourceServerResp.getBody(String).get() == "Your father is Rhaegar Targaryen"
    }

    void 'test client credentials token caching'() {
        given:
        ClientCredentialsClient clientCredentialsClient = applicationContext.getBean(ClientCredentialsClient, Qualifiers.byName("authservermanual"))

        when:
        authServer.applicationContext.getBean(TokenController).down = true
        TokenResponse tokenResponse = Flowable.fromPublisher(clientCredentialsClient.requestToken()).blockingFirst()

        then:
        noExceptionThrown()

        when:
        String accessToken = tokenResponse.accessToken
        HttpRequest<?> resourceServerRequest = HttpRequest.GET('/father').accept(MediaType.TEXT_PLAIN).bearerAuth(accessToken)
        HttpResponse<String> resourceServerResp = resourceServerClient.exchange(resourceServerRequest, String)

        then:
        noExceptionThrown()
        resourceServerResp.status() == HttpStatus.OK
        resourceServerResp.getBody(String).isPresent()
        resourceServerResp.getBody(String).get() == "Your father is Rhaegar Targaryen"

        when: 'calling client credentials returns the old access token'
        authServer.applicationContext.getBean(TokenController).down = false
        tokenResponse = Flowable.fromPublisher(clientCredentialsClient.requestToken()).blockingFirst()

        then:
        tokenResponse.accessToken == accessToken

        when: 'calling client credentials with different scope returns a different access token'
        tokenResponse = Flowable.fromPublisher(clientCredentialsClient.requestToken("email")).blockingFirst()

        then:
        tokenResponse.accessToken != accessToken

        when: 'wait 6 seconds, the access token should be expired'
        sleep(6_000)
        resourceServerClient.exchange(resourceServerRequest, String)

        then:
        HttpClientResponseException resourceResp = thrown()
        resourceResp.status == HttpStatus.UNAUTHORIZED

        when: 'calling client credentials returns the new token because the previous token is detected as expired'
        authServer.applicationContext.getBean(TokenController).down = false
        tokenResponse = Flowable.fromPublisher(clientCredentialsClient.requestToken()).blockingFirst()

        then:
        tokenResponse.accessToken != accessToken

        when: 'moreover, calling client credentials with force true returns a different access token'
        accessToken = tokenResponse.accessToken
        tokenResponse = Flowable.fromPublisher(clientCredentialsClient.requestToken(true)).blockingFirst()

        then:
        tokenResponse.accessToken != accessToken
    }

    void "it is possible to add an access token via a client credentials request and an HTTP Client filter"() {
        when:
        ResourceClient resourceClient = applicationContext.getBean(ResourceClient)
        String father = resourceClient.father()

        then:
        noExceptionThrown()
        "Your father is Rhaegar Targaryen" == father
    }

    @Requires(property = 'spec.name', value = 'ClientCredentialsSpec')
    @Client(id="resourceclient")
    static interface ResourceClient {
        @Consumes(MediaType.TEXT_PLAIN)
        @Get("/father")
        String father();
    }

    @Requires(property = 'spec.name', value = 'ClientCredentialsSpecAuthServerDown')
    @Controller("/.well-known")
    static class OpenIdConfigurationAuthServerDownController {
        private final String url
        private final List<AuthenticationMethod> authenticationMethods

        OpenIdConfigurationAuthServerDownController(@Property(name = "micronaut.server.port") Integer port) {
            this.url = "http://localhost:$port"
            this.authenticationMethods = [
                    AuthenticationMethod.CLIENT_SECRET_POST,
                    AuthenticationMethod.CLIENT_SECRET_BASIC
            ]
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/openid-configuration")
        Map<String, Object> index() {
            Map<String, Object> conf = [
                    "token_endpoint": "${url}/token".toString(),
                    "token_endpoint_auth_methods_supported": authenticationMethods.collect {it.toString()},
                    "grant_types_supported": [
                            "client_credentials"
                    ]
            ]
            conf
        }
    }

    @Requires(property = 'spec.name', value = 'ClientCredentialsSpecAuthServerDown')
    @Controller("/token")
    static class TokenAuthServerDownController {
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Post
        HttpResponse<?> index() {
            HttpResponse.serverError()
        }
    }

    @Requires(property = 'spec.name', value = 'ClientCredentialsSpecAuthServer')
    @Controller("/.well-known")
    static class OpenIdConfigurationController {
        private final String url
        private final List<AuthenticationMethod> authenticationMethods

        OpenIdConfigurationController(@Property(name = "micronaut.server.port") Integer port) {
            this.url = "http://localhost:$port"
            this.authenticationMethods = [
                    AuthenticationMethod.CLIENT_SECRET_POST,
                    AuthenticationMethod.CLIENT_SECRET_BASIC
            ]
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/openid-configuration")
        Map<String, Object> index() {
            Map<String, Object> conf = [
            "token_endpoint": "${url}/token".toString(),
            "token_endpoint_auth_methods_supported": authenticationMethods.collect {it.toString()},
            "grant_types_supported": [
                    "client_credentials"
            ]
            ]
            conf
        }
    }

    @Requires(property = 'spec.name', value = 'ClientCredentialsSpecAuthServer')
    @Controller("/token")
    static class TokenController {
        private final JwtTokenGenerator jwtTokenGenerator
        private final SampleClientConfiguration sampleClientConfiguration
        private final AccessTokenConfiguration accessTokenConfiguration
        private final Integer tokenExpiration

        boolean down
        TokenController(JwtTokenGenerator jwtTokenGenerator,
                        SampleClientConfiguration sampleClientConfiguration,
                        AccessTokenConfiguration accessTokenConfiguration,
                        @Property(name = 'micronaut.security.token.jwt.generator.access-token.expiration') Integer tokenExpiration) {
            this.jwtTokenGenerator = jwtTokenGenerator
            this.sampleClientConfiguration = sampleClientConfiguration
            this.accessTokenConfiguration = accessTokenConfiguration
            this.tokenExpiration = tokenExpiration;
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Post
        HttpResponse<?> index(String grant_type,
                              @Nullable String client_id,
                              @Nullable String client_secret,
                              @Nullable @Header String authorization) {
            if (down) {
                return HttpResponse.serverError()
            }
            if (grant_type != GrantType.CLIENT_CREDENTIALS.toString()) {
                return HttpResponse.badRequest([error: 'invalid_grant'])
            }

            if (!validate(client_id, client_id, authorization)) {
                return HttpResponse.status(HttpStatus.UNAUTHORIZED).body([error: 'invalid_client'])
            }

            TokenResponse tokenResponse = new TokenResponse()
            tokenResponse.tokenType = 'bearer'
            tokenResponse.expiresIn = tokenExpiration
            UserDetails userDetails = new UserDetails('john', [])
            tokenResponse.accessToken = jwtTokenGenerator.generateToken(userDetails, accessTokenConfiguration.getExpiration()).get()
            HttpResponse.ok(tokenResponse)
        }

        private boolean validate(@Nullable String client_id,
                                 @Nullable String client_secret,
                                 @Nullable String authorization) {
            boolean isValid = false
            if (authorization != null) {
                Optional<UsernamePasswordCredentials> credentialsOptional = BasicAuthUtils.parseCredentials(authorization)
                if (credentialsOptional.isPresent()) {
                    UsernamePasswordCredentials creds = credentialsOptional.get()
                    if (sampleClientConfiguration.clientSecret == creds.password && sampleClientConfiguration.clientId == creds.username) {
                        isValid = true
                    }
                }
            }
            if (client_id != null && client_secret != null) {
                if (sampleClientConfiguration.clientSecret == client_secret && sampleClientConfiguration.clientId == client_id) {
                    isValid = true
                }
            }
            isValid
        }
    }

    @Requires(property = 'spec.name', value = 'ClientCredentialsSpecResourceServer')
    @Controller("/father")
    static class ResourceServerController {

        @Produces(MediaType.TEXT_PLAIN)
        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Get
        String index() {
            "Your father is Rhaegar Targaryen"
        }
    }

    @Requires(property = 'spec.name', value = 'ClientCredentialsSpecAuthServer')
    @ConfigurationProperties("sample")
    static class SampleClientConfiguration {

        @NonNull
        @NotBlank
        private String clientId

        @NonNull
        @NotBlank
        private String clientSecret

        @NonNull
        String getClientId() {
            return clientId
        }

        void setClientId(@NonNull String clientId) {
            this.clientId = clientId
        }

        @NonNull
        String getClientSecret() {
            return clientSecret
        }

        void setClientSecret(@NonNull String clientSecret) {
            this.clientSecret = clientSecret
        }
    }

    @Requires(property = 'spec.name', value = 'ClientCredentialsSpecAuthServer')
    @Singleton
    static class CustomJwtIdGenerator implements JwtIdGenerator {

        @Override
        String generateJtiClaim() {
            UUID.randomUUID().toString()
        }
    }

    @Requires(property = 'spec.name', value = 'ClientCredentialsSpecAuthServer')
    @ConfigurationProperties("authserver.config")
    static class CustomJwkConfiguration {
        @NonNull
        @NotBlank
        private String jwk

        String getJwk() {
            return jwk
        }

        void setJwk(@NonNull String jwk) {
            this.jwk = jwk
        }
    }

    @Requires(property = 'spec.name', value = 'ClientCredentialsSpecAuthServer')
    @Named("generator")
    @Singleton
    static class MdxAuthRSASignatureConfiguration implements RSASignatureGeneratorConfiguration, JwkProvider {
        private static final Logger LOG = LoggerFactory.getLogger(MdxAuthRSASignatureConfiguration.class);

        private final RSAKey rsaKey;

        MdxAuthRSASignatureConfiguration(CustomJwkConfiguration mdxAuthConfiguration) {
            try {
                JWK jwk = JWK.parse(mdxAuthConfiguration.getJwk());
                if (!(jwk instanceof RSAKey)) {
                    if (LOG.isErrorEnabled()) {
                        LOG.error("JWK is not an RSAKey");
                    }
                    throw new ConfigurationException("JWK is not an RSAKey");
                }
                this.rsaKey = (RSAKey) jwk;
            } catch (ParseException e) {
                if (LOG.isErrorEnabled()) {
                    LOG.error("Could not parse JWK JSON string {}", mdxAuthConfiguration.getJwk());
                }
                throw new ConfigurationException("could not parse JWK JSON String");
            }
        }

        @Override
        RSAPrivateKey getPrivateKey() {
            try {
                return rsaKey.toRSAPrivateKey();
            } catch (JOSEException e) {
                if (LOG.isErrorEnabled()) {
                    LOG.error("Could not get rsa private key {}", e.getMessage());
                }
                return null;
            }
        }

        @Override
        JWSAlgorithm getJwsAlgorithm() {
            Algorithm algorithm = rsaKey.getAlgorithm();
            if (algorithm instanceof JWSAlgorithm) {
                return (JWSAlgorithm) algorithm;
            }
            if (algorithm != null) {
                return JWSAlgorithm.parse(algorithm.getName());
            }

            if (LOG.isErrorEnabled()) {
                LOG.error("algorithm is not a JWSAlgorithm");
            }
            return null;
        }

        @Override
        RSAPublicKey getPublicKey() {
            try {
                return rsaKey.toRSAPublicKey();
            } catch (JOSEException e) {
                if (LOG.isErrorEnabled()) {
                    LOG.error("Could not get rsa public key {}", e.getMessage());
                }
                return null;
            }
        }

        @Override
        List<JWK> retrieveJsonWebKeys() {
            return Collections.singletonList(rsaKey.toPublicJWK());
        }
    }

    static String jwkJsonString() {
        '{"p":"94qBOZGhF9GKlSgqijO21jaSRzOc-566PUEdhHWtpZ3HITnkefOB7MWMXceDHtOonc4xKvXB5cYtBP7gMx96MNhtYnRWuVgy81cqV94DVZdg5C4D5irU7DgnXGS4Tgjhs2oIVG7QhhQFt-KhbmvDKIiGJAx7ZMgFqXyokJ6SUCk","kty":"RSA","q":"m1GYyXCuB4-nIG7SV7D9HOhYauKMMyiQGgz0DtNZPqydlbt3i8QTOQubBO2KvT08ttl0b2agXFVBYf9RduXucqDa0WZzs1YUzVh-1_74w_8Zc7gu1wy0mzkl3Yd4IOJ9Fdrr581TJ5ZnUYJdmtkSEwo5oVU4n1FZO-ES-RvDy18","d":"e0tWV2oNFlpuwBhtB4j6-E7NSAV9IVaGG1UMjRdpiZX2GaRX6stOfPSvXwZtlJmUgbKDjnlmUgNP85INmsw7VTH4hBuLt6QB4BAKDEJwk33eqPHyU_iDsc7xYQ2D-59cbW6-1GHJ0g1O5iqrJ_UvrT59jX6OjQxU9Hccgvmg0ZxhZHS_wwmVh6ZFCNNiX8OnVH4S7iCxyRvziK5IX2RzEu9OBgb5MXdjQKmnfhNsoDW_CvQiabR5kh4k7FY1DofaL501ZisPAw4kaGzSHvvj9efWn58COu-KR2FcoT-8k0kc661_3khSGsbDIozE9axPV2NdtnY0efQuzKaoqou44Q","e":"AQAB","use":"sig","kid":"90d044ec76524c018e6705993698d3d1","qi":"rJRGiabf3AwG7lJQSNDYKjC1zGcE7yU5gWxdhuFTKfNBxTezDZ1ISJIrfycIJ2B4c4UjqyErbmpOkzeYCwmZ7temoqNRSU2T9JR9tRPUdivtxqYyFNqdjqGwLHgCeVzSVNLbbYE6vTC8dvUd6O5-SQEN-eEpxnzalYGJXdnO0pw","dp":"4CFlTgXA0XslulXK5qVaV-zDV3qxGdanFE0_965BUuJf6YKsj4reyc44gLTj0OaeFnwaYqZwMKbWHl7UCxXmIhHkQK_L0je8sj3rFfHsHPRag1_yodWIQnW5lduQUP-TtEo-Toyje7LnVo750av64Vlz83Hly-Ob1NENIxygp7k","alg":"RS256","dq":"bq7sUYkiC7NcZylybhlrluEguTKutHpQjq_ycGo-rAI43o5Ut95H0JwroYxiFU-BZ9B5QDYDSylaSaq39CIRFdD5fsYi54cNlfRdmDFUN-Af1C5J-uhMAF3uVPsIKW8dsqhq-qqAerKc-CIN8J6GWdksjoL7sdU34QsZCTq3AcM","n":"li_CzcPSIgwcLjUlEOuPrMJZ2RdZYbjVeutDZUhYsoZZxo0_3DvYVkWCWCsS8UYwQ3xHwhdMxAuLDrZbve1R6grbV-JO3isAj9IQotPWpqmSsHScNf2LDge5Mrn-MoKB_1lU2nX5t-s4g-eHubuTVaXuaeYT3kmlsYJelWrSAPanVV6UCZ1SQpQ8UX3h79jDpO7cb3XzbvVJZ4_pBEjXq0C84ksbp4pvimT3fpY2rd7FNVd_wwgbLbEbh8cRfwXXzUBsSKZh0rlWa2VxRyFmLLPTJKl0h9XWTyVLrG5kwFOCohBy_bjs75EG9u3sZfcp1VHLpvGmBV7Sy00xQBdCNw"}'
    }

    static String getSecondaryJwkJsonString() {
        '{"p":"7_Sb8vKE0I9DoN-AzA9BHTkDG8xc7T_3D7kuycLUkiqxyVscF6b8DDz6KNn1GHKOHpQakA2HYCtYcRsQpBIPb9RTpVTyjl3Rhmn6pZQH-IOPeqBsQqpUvwuqB52ha80TA6DPFWJQL9bE7MAaciiyunU-z3xA1TkO7RgIawu2_PU","kty":"RSA","q":"p_ryu_hzAn5vN1Sn6I9GCTiLgtmlXkfFv9oNZMBKF9mga5Fxm1TzNgIKu6PueC4_HzBnG1SbpzYLaJ6eFkgja5QCp9hjQrW9hnMEPELZeLRfUCvRzzTDd9p8UyjYOjmFwnhLR9RfrNepdd-6D8YnD0xtTELQI-P5oB38f5A8Js0","d":"WxfObX7wxpBxaTbIDbV7-fXXVoBVIXMEMIBIMTQFjIwU0an_Vxlq-tT0cLOuJulabAJvekfKlWU7deruyAjiAy6MKU2C7vpZkWaITYA016IVt5GHHhg3rCxMH2FXcooneCxXhrm5dN3Fe66lVIkRe67amSiRe6DCH63w9TnT5B4N7nlBhcMO1BWi8KcbCsz0Rr2ajD_xPo3wS-MW_S2v8oWchgBYK6ELTxFhQrDqjCkR-iCUbqmNtfVfUmY_3oKJRqIrwzydllBKIES876OcXKNd-dGvkHLUo0yStzFNaLbpC1lSRYolnHPlKWs92T03qlRowBf0QCOOpFf9BEnkQQ","e":"AQAB","use":"sig","kid":"05f5ff8b2895430ea0ed52f116c3ec14","qi":"GaLS5pwbEkYCvdDDdb8_vVu_gkpftc7d-n4ODeu3481m5PPW5z1M2zAXWuUqW29wWKZznx_LY35ahS4YZ0pJm2qrgB8V6zJa2TARL4PI67-xoNgKTM7pPO-8E6XrJIMQAiRLrTLLfygaZyoB7Ac9jkXn1O_nhEuRCXhHvttG7yk","dp":"DDT_cf6QbyO6pwZ3wOnNwDTUSae92nv0j6I2FSGKOt1dKgcuiK2ACQdZGpbr9xBs1nVmXImzp1rNJwPfdtlMW74Le0-0_zUaoaHmlGHRff0DYZOjrkiIAygOwFBuk9Nc8kROBKJ5vdVJM1oaflA_t2ibh2akzbQXZExisT9pUbk","alg":"RS256","dq":"Oh0udutoVpeJQHowMNvIXg5K7bUAahKojkwQ0CdaOtAWmMBTrmqATdH9BpebO8a8Hb0wHptx0jJ3VfVyOcExR9mH5auOA5k-fVIzR-nUtNaqFuFiD65wZXmYA2khDVuzM-lMGgiWJQTjYp1JEIX8I2XMdlKzEYegZ82X-kXbGY0","n":"nXPKITNv0cWqIPMuIaJZ0l7NtxQlENOOs7w3iVwBMTDdcVc2bTjBgeBllbN0SG37VkQwe4aAQ7uEDw8g8RAVQUelM4OGqRmUUjXPQKGgSS6RvcYIsZgPzUDmZSa_Sk6ofF3EOiCuBicDmgyXlcwiD5zDsXwdhSIKbXyyKPYmY-Q5QKdy399AgeLbRWBWihxN0V0mxs_2xZrvq_8ViE9I0eHnp3mssPifgJjP_m4lhn6HtSE3rhEt_0tPSRnFs0-sEnNuZ8EKUvvrMHCXDzGuJerQEnxNrfU4etT4CS7J_Fz99sQWZLW3gpvgRSSh8Iu-aRbxL8WEhkdVtfgtpIDuMQ"}'
    }
}
