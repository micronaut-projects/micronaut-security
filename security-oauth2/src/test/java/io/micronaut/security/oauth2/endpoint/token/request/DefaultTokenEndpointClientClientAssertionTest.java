/*
 * Copyright 2017-2026 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.oauth2.endpoint.token.request;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.client.DefaultHttpClientConfiguration;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.HttpClientConfiguration;
import io.micronaut.http.server.util.HttpHostResolver;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OauthClientConfigurationProperties;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.SecureEndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.AuthenticationMethods;
import io.micronaut.security.oauth2.endpoint.DefaultSecureEndpoint;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.token.request.context.TokenRequestContext;
import io.micronaut.security.oauth2.endpoint.token.response.TokenErrorResponse;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import io.micronaut.security.oauth2.grants.SecureGrant;
import io.micronaut.security.oauth2.grants.SecureGrantMap;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.token.jwt.signature.SignatureGeneratorConfiguration;
import io.micronaut.runtime.server.EmbeddedServer;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DefaultTokenEndpointClientClientAssertionTest {

    private static final String TOKEN_URL = "https://authorization-server.example.com/oauth/token";
    private static final String CLIENT_ID = "client-id";
    private static final String CLIENT_SECRET = "012345678901234567890123456789012345678901234567";
    private static final String CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private static final String INTEGRATION_SPEC_NAME = "DefaultTokenEndpointClientClientAssertionIntegrationTest";

    @Test
    void clientSecretBasicBehaviorIsUnchanged() {
        try (ApplicationContext context = ApplicationContext.run()) {
            ExposedTokenEndpointClient client = client(context);
            Map<String, String> grant = new SecureGrantMap();
            MutableHttpRequest<Map<String, String>> request = request(grant);

            client.secure(request, context(AuthenticationMethods.CLIENT_SECRET_BASIC, clientConfiguration(CLIENT_SECRET, Optional.empty(), Optional.empty())));

            assertTrue(request.getHeaders().contains("Authorization"));
            assertFalse(grant.containsKey(SecureGrant.KEY_CLIENT_ID));
            assertFalse(grant.containsKey(SecureGrant.KEY_CLIENT_SECRET));
        }
    }

    @Test
    void clientSecretPostBehaviorIsUnchanged() {
        try (ApplicationContext context = ApplicationContext.run()) {
            ExposedTokenEndpointClient client = client(context);
            Map<String, String> grant = new SecureGrantMap();
            MutableHttpRequest<Map<String, String>> request = request(grant);

            client.secure(request, context(AuthenticationMethods.CLIENT_SECRET_POST, clientConfiguration(CLIENT_SECRET, Optional.empty(), Optional.empty())));

            assertFalse(request.getHeaders().contains("Authorization"));
            assertEquals(CLIENT_ID, grant.get(SecureGrant.KEY_CLIENT_ID));
            assertEquals(CLIENT_SECRET, grant.get(SecureGrant.KEY_CLIENT_SECRET));
        }
    }

    @Test
    void clientSecretJwtAddsClientAssertionParameters() throws ParseException, JOSEException {
        try (ApplicationContext context = ApplicationContext.run()) {
            ExposedTokenEndpointClient client = client(context);
            OauthClientConfigurationProperties.TokenEndpointConfigurationProperties token = tokenEndpointConfiguration();
            OauthClientConfigurationProperties.TokenEndpointConfigurationProperties.ClientAssertionConfigurationProperties clientAssertion = new OauthClientConfigurationProperties.TokenEndpointConfigurationProperties.ClientAssertionConfigurationProperties();
            clientAssertion.setLifetime(Duration.ofMinutes(2));
            clientAssertion.setIssuer("issuer");
            clientAssertion.setSubject("subject");
            clientAssertion.setAudience("audience");
            clientAssertion.setSigningAlgorithm("HS384");
            token.setClientAssertion(clientAssertion);
            Map<String, String> grant = new SecureGrantMap();
            grant.put(SecureGrant.KEY_CLIENT_SECRET, "must-be-removed");
            MutableHttpRequest<Map<String, String>> request = request(grant);

            client.secure(request, context(AuthenticationMethods.CLIENT_SECRET_JWT, clientConfiguration(CLIENT_SECRET, Optional.of(token), Optional.empty())));

            assertFalse(request.getHeaders().contains("Authorization"));
            assertEquals(CLIENT_ID, grant.get(SecureGrant.KEY_CLIENT_ID));
            assertFalse(grant.containsKey(SecureGrant.KEY_CLIENT_SECRET));
            assertEquals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", grant.get("client_assertion_type"));
            SignedJWT jwt = SignedJWT.parse(grant.get("client_assertion"));
            assertEquals(JWSAlgorithm.HS384, jwt.getHeader().getAlgorithm());
            assertTrue(jwt.verify(new MACVerifier(CLIENT_SECRET)));
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            assertEquals("issuer", claims.getIssuer());
            assertEquals("subject", claims.getSubject());
            assertEquals(List.of("audience"), claims.getAudience());
            assertNotNull(claims.getIssueTime());
            assertNotNull(claims.getExpirationTime());
            assertNotNull(claims.getJWTID());
        }
    }

    @Test
    void sendRequestPostsClientAssertionAcceptedByTokenEndpoint() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", INTEGRATION_SPEC_NAME))) {
            ApplicationContext context = server.getApplicationContext();
            try (HttpClient httpClient = context.createBean(HttpClient.class, server.getURL())) {
                context.registerSingleton(HttpClient.class, httpClient, Qualifiers.byName("test"));
                TokenRequestContext<Map<String, String>, TokenResponse> requestContext = context(
                        server.getURL() + "/token",
                        AuthenticationMethods.CLIENT_SECRET_JWT,
                        clientConfiguration(CLIENT_SECRET, Optional.empty(), Optional.empty())
                );

                TokenResponse tokenResponse = Flux.from(client(context).sendRequest(requestContext)).blockFirst();

                assertNotNull(tokenResponse);
                assertEquals("accepted", tokenResponse.getAccessToken());
            }
        }
    }

    @Test
    void clientSecretJwtGeneratesAssertionPerRequest() throws ParseException {
        try (ApplicationContext context = ApplicationContext.run()) {
            ExposedTokenEndpointClient client = client(context);
            OauthClientConfiguration clientConfiguration = clientConfiguration(CLIENT_SECRET, Optional.empty(), Optional.empty());
            Map<String, String> firstGrant = new SecureGrantMap();
            Map<String, String> secondGrant = new SecureGrantMap();

            client.secure(request(firstGrant), context(AuthenticationMethods.CLIENT_SECRET_JWT, clientConfiguration));
            client.secure(request(secondGrant), context(AuthenticationMethods.CLIENT_SECRET_JWT, clientConfiguration));

            assertNotEquals(
                    SignedJWT.parse(firstGrant.get("client_assertion")).getJWTClaimsSet().getJWTID(),
                    SignedJWT.parse(secondGrant.get("client_assertion")).getJWTClaimsSet().getJWTID()
            );
        }
    }

    @Test
    void privateKeyJwtUsesConfiguredSigner() throws ParseException {
        try (ApplicationContext context = ApplicationContext.run(Map.of("spec.name", "private-key-jwt"))) {
            ExposedTokenEndpointClient client = client(context);
            OauthClientConfigurationProperties.TokenEndpointConfigurationProperties token = tokenEndpointConfiguration();
            OauthClientConfigurationProperties.TokenEndpointConfigurationProperties.ClientAssertionConfigurationProperties clientAssertion = new OauthClientConfigurationProperties.TokenEndpointConfigurationProperties.ClientAssertionConfigurationProperties();
            clientAssertion.setSignerName("assertion");
            token.setClientAssertion(clientAssertion);
            Map<String, String> grant = new SecureGrantMap();

            client.secure(request(grant), context(AuthenticationMethods.PRIVATE_KEY_JWT, clientConfiguration(null, Optional.of(token), Optional.empty())));

            SignedJWT jwt = SignedJWT.parse(grant.get("client_assertion"));
            assertEquals(JWSAlgorithm.RS256, jwt.getHeader().getAlgorithm());
            assertEquals("assertion-kid", jwt.getHeader().getKeyID());
            assertEquals(CLIENT_ID, jwt.getJWTClaimsSet().getIssuer());
            assertEquals(CLIENT_ID, jwt.getJWTClaimsSet().getSubject());
            assertEquals(List.of(TOKEN_URL), jwt.getJWTClaimsSet().getAudience());
        }
    }

    @Test
    void missingClientSecretFailsClosed() {
        try (ApplicationContext context = ApplicationContext.run()) {
            ExposedTokenEndpointClient client = client(context);

            ConfigurationException exception = assertThrows(ConfigurationException.class,
                    () -> client.secure(request(new SecureGrantMap()), context(AuthenticationMethods.CLIENT_SECRET_JWT, clientConfiguration(null, Optional.empty(), Optional.empty()))));

            assertTrue(exception.getMessage().contains("requires a client secret"));
        }
    }

    @Test
    void missingPrivateKeySignerFailsClosed() {
        try (ApplicationContext context = ApplicationContext.run()) {
            ExposedTokenEndpointClient client = client(context);

            ConfigurationException exception = assertThrows(ConfigurationException.class,
                    () -> client.secure(request(new SecureGrantMap()), context(AuthenticationMethods.PRIVATE_KEY_JWT, clientConfiguration(null, Optional.empty(), Optional.empty()))));

            assertTrue(exception.getMessage().contains("requires a SignatureGeneratorConfiguration bean"));
        }
    }

    private static MutableHttpRequest<Map<String, String>> request(Map<String, String> grant) {
        return HttpRequest.POST(TOKEN_URL, grant);
    }

    private static TokenRequestContext<Map<String, String>, TokenResponse> context(String authenticationMethod,
                                                                                   OauthClientConfiguration clientConfiguration) {
        return new TestTokenRequestContext(new DefaultSecureEndpoint(TOKEN_URL, Set.of(authenticationMethod)), clientConfiguration);
    }

    private static TokenRequestContext<Map<String, String>, TokenResponse> context(String url,
                                                                                   String authenticationMethod,
                                                                                   OauthClientConfiguration clientConfiguration) {
        return new TestTokenRequestContext(new DefaultSecureEndpoint(url, Set.of(authenticationMethod)), clientConfiguration);
    }

    private static OauthClientConfiguration clientConfiguration(String clientSecret,
                                                               Optional<SecureEndpointConfiguration> token,
                                                               Optional<OpenIdClientConfiguration> openid) {
        OauthClientConfiguration clientConfiguration = mock(OauthClientConfiguration.class);
        when(clientConfiguration.getName()).thenReturn("test");
        when(clientConfiguration.getClientId()).thenReturn(CLIENT_ID);
        when(clientConfiguration.getClientSecret()).thenReturn(clientSecret);
        when(clientConfiguration.getToken()).thenReturn(token);
        when(clientConfiguration.getOpenid()).thenReturn(openid);
        return clientConfiguration;
    }

    private static OauthClientConfigurationProperties.TokenEndpointConfigurationProperties tokenEndpointConfiguration() {
        OauthClientConfigurationProperties.TokenEndpointConfigurationProperties token = new OauthClientConfigurationProperties.TokenEndpointConfigurationProperties();
        token.setUrl(TOKEN_URL);
        return token;
    }

    private static ExposedTokenEndpointClient client(ApplicationContext context) {
        return new ExposedTokenEndpointClient(
                context,
                new DefaultHttpClientConfiguration(),
                context.findBean(DefaultTokenEndpointClient.ClientAssertionGenerator.class)
        );
    }

    private static final class ExposedTokenEndpointClient extends DefaultTokenEndpointClient {

        ExposedTokenEndpointClient(ApplicationContext beanContext,
                                   HttpClientConfiguration defaultClientConfiguration,
                                   Optional<ClientAssertionGenerator> clientAssertionGenerator) {
            super(beanContext, defaultClientConfiguration, clientAssertionGenerator);
        }

        void secure(MutableHttpRequest<Map<String, String>> request,
                    TokenRequestContext<Map<String, String>, TokenResponse> requestContext) {
            secureRequest(request, requestContext);
        }
    }

    private record TestTokenRequestContext(SecureEndpoint endpoint,
                                           OauthClientConfiguration clientConfiguration) implements TokenRequestContext<Map<String, String>, TokenResponse> {

        @Override
        public Map<String, String> getGrant() {
            return new HashMap<>();
        }

        @Override
        public Argument<TokenResponse> getResponseType() {
            return Argument.of(TokenResponse.class);
        }

        @Override
        public Argument<?> getErrorResponseType() {
            return Argument.of(TokenErrorResponse.class);
        }

        @Override
        public MediaType getMediaType() {
            return MediaType.APPLICATION_FORM_URLENCODED_TYPE;
        }

        @Override
        public SecureEndpoint getEndpoint() {
            return endpoint;
        }

        @Override
        public OauthClientConfiguration getClientConfiguration() {
            return clientConfiguration;
        }
    }

    @Singleton
    @Named("assertion")
    @Requires(property = "spec.name", value = "private-key-jwt")
    static final class TestRsaSignatureGenerator implements SignatureGeneratorConfiguration {
        private static final KeyPair KEY_PAIR = keyPair();

        @Override
        public SignedJWT sign(JWTClaimsSet claims) throws JOSEException {
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("assertion-kid").build(), claims);
            jwt.sign(new RSASSASigner((RSAPrivateKey) KEY_PAIR.getPrivate()));
            return jwt;
        }

        @Override
        public String supportedAlgorithmsMessage() {
            return "Only RSA algorithms are supported";
        }

        @Override
        public boolean supports(JWSAlgorithm algorithm) {
            return JWSAlgorithm.Family.RSA.contains(algorithm);
        }

        @Override
        public boolean verify(SignedJWT jwt) throws JOSEException {
            return jwt.verify(new RSASSAVerifier((RSAPublicKey) KEY_PAIR.getPublic()));
        }

        private static KeyPair keyPair() {
            try {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
                generator.initialize(2048);
                return generator.generateKeyPair();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    @Controller("/token")
    @Requires(property = "spec.name", value = INTEGRATION_SPEC_NAME)
    static final class ClientAssertionTokenController {
        private final HttpHostResolver httpHostResolver;

        ClientAssertionTokenController(HttpHostResolver httpHostResolver) {
            this.httpHostResolver = httpHostResolver;
        }

        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Secured(SecurityRule.IS_ANONYMOUS)
        @Post
        HttpResponse<TokenResponse> token(HttpRequest<?> request, @Body Map<String, String> body) throws ParseException, JOSEException {
            if (!CLIENT_ID.equals(body.get(SecureGrant.KEY_CLIENT_ID))) {
                return HttpResponse.badRequest();
            }
            if (body.containsKey(SecureGrant.KEY_CLIENT_SECRET)) {
                return HttpResponse.badRequest();
            }
            if (!CLIENT_ASSERTION_TYPE.equals(body.get("client_assertion_type"))) {
                return HttpResponse.badRequest();
            }
            String clientAssertion = body.get("client_assertion");
            if (clientAssertion == null) {
                return HttpResponse.badRequest();
            }
            SignedJWT jwt = SignedJWT.parse(clientAssertion);
            if (!jwt.verify(new MACVerifier(CLIENT_SECRET))) {
                return HttpResponse.badRequest();
            }
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            String tokenUrl = httpHostResolver.resolve(request) + request.getPath();
            if (!CLIENT_ID.equals(claims.getIssuer())
                    || !CLIENT_ID.equals(claims.getSubject())
                    || !claims.getAudience().contains(tokenUrl)
                    || claims.getJWTID() == null) {
                return HttpResponse.badRequest();
            }
            return HttpResponse.ok(new TokenResponse("accepted", "bearer"));
        }
    }
}
