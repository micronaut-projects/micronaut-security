package io.micronaut.security.oauth2.endpoint.token.request.clientauth;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.exceptions.BeanInstantiationException;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Header;
import io.micronaut.http.annotation.Post;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.oauth2.client.clientcredentials.ClientCredentialsClient;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.AuthenticationMethods;
import io.micronaut.security.oauth2.endpoint.DefaultSecureEndpoint;
import io.micronaut.security.oauth2.endpoint.token.request.TokenEndpointClient;
import io.micronaut.security.oauth2.endpoint.token.request.context.ClientCredentialsTokenRequestContext;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import io.micronaut.security.oauth2.grants.ClientCredentialsGrant;
import io.micronaut.security.oauth2.grants.SecureGrant;
import io.micronaut.security.oauth2.grants.SecureGrantMap;
import io.micronaut.security.rules.SecurityRule;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class PrivateKeyJwtAuthenticationTest {

    private static final String CLIENT = "jwt-client";
    private static final String CLIENT_ID = "client-id-fixture";
    private static final String PREFIX = "micronaut.security.oauth2.clients." + CLIENT + ".";
    private static final String ACCESS_TOKEN = "access-token-fixture-not-a-secret";
    private static final String REMOTE_ASSERTION = "header.payload.signature";
    private static final String ISSUER_IDENTIFIER = "https://issuer.example";

    @Test
    void localSigningWithPkcs8EcKey() throws Exception {
        KeyPair keyPair = ecKeyPair("secp256r1");
        try (EmbeddedServer authServer = authServer()) {
            Map<String, Object> config = privateKeyJwtConfig(authServer);
            config.put(PREFIX + "token.client-assertion.algorithm", "ES256");
            config.put(PREFIX + "token.client-assertion.key-id", "kid-fixture");
            config.put(PREFIX + "token.client-assertion.private-key", pem("PRIVATE KEY", keyPair.getPrivate().getEncoded()));
            try (ApplicationContext ctx = ApplicationContext.run(config)) {
                assertTokenResponse(ctx);
                CapturedRequest request = captured(authServer);
                assertPrivateKeyJwtRequest(request);

                SignedJWT jwt = SignedJWT.parse(request.form().get(SecureGrant.KEY_CLIENT_ASSERTION));
                assertEquals("ES256", jwt.getHeader().getAlgorithm().getName());
                assertEquals("kid-fixture", jwt.getHeader().getKeyID());
                assertTrue(jwt.verify(new ECDSAVerifier((ECPublicKey) keyPair.getPublic())));
                JWTClaimsSet claims = jwt.getJWTClaimsSet();
                assertEquals(CLIENT_ID, claims.getIssuer());
                assertEquals(CLIENT_ID, claims.getSubject());
                assertEquals(List.of(ISSUER_IDENTIFIER), claims.getAudience());
                assertNotNull(claims.getJWTID());
                assertFalse(claims.getIssueTime().after(new Date()));
                assertEquals(60_000, claims.getExpirationTime().getTime() - claims.getIssueTime().getTime());
            }
        }
    }

    @Test
    void eachInvocationGeneratesANewClientAssertion() throws Exception {
        KeyPair keyPair = ecKeyPair("secp256r1");
        try (EmbeddedServer authServer = authServer()) {
            Map<String, Object> config = privateKeyJwtConfig(authServer);
            config.put(PREFIX + "token.client-assertion.algorithm", "ES256");
            config.put(PREFIX + "token.client-assertion.private-key", pem("PRIVATE KEY", keyPair.getPrivate().getEncoded()));
            try (ApplicationContext ctx = ApplicationContext.run(config)) {
                ClientAssertionGenerator generator = ctx.getBean(ClientAssertionGenerator.class, Qualifiers.byName(CLIENT));
                String issuerIdentifier = "https://another-issuer.example";
                Publisher<String> assertion = generator.generateAssertion(CLIENT_ID, issuerIdentifier);
                String firstAssertion = Mono.from(assertion).block();
                String secondAssertion = Mono.from(assertion).block();
                assertNotNull(firstAssertion);
                assertNotNull(secondAssertion);
                assertEquals(List.of(issuerIdentifier), SignedJWT.parse(firstAssertion).getJWTClaimsSet().getAudience());
                assertNotEquals(firstAssertion, secondAssertion);
                assertNotEquals(SignedJWT.parse(firstAssertion).getJWTClaimsSet().getJWTID(),
                    SignedJWT.parse(secondAssertion).getJWTClaimsSet().getJWTID());
            }
        }
    }

    @Test
    void localSigningWithPkcs8RsaKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        try (EmbeddedServer authServer = authServer()) {
            Map<String, Object> config = privateKeyJwtConfig(authServer);
            config.put(PREFIX + "token.client-assertion.private-key", pem("PRIVATE KEY", keyPair.getPrivate().getEncoded()));
            try (ApplicationContext ctx = ApplicationContext.run(config)) {
                assertTokenResponse(ctx);
                CapturedRequest request = captured(authServer);
                assertPrivateKeyJwtRequest(request);

                SignedJWT jwt = SignedJWT.parse(request.form().get(SecureGrant.KEY_CLIENT_ASSERTION));
                assertEquals("RS256", jwt.getHeader().getAlgorithm().getName());
                assertTrue(jwt.verify(new RSASSAVerifier((RSAPublicKey) keyPair.getPublic())));
            }
        }
    }

    @Test
    void localSigningWithPkcs1RsaKeyFromFileAndConfiguredIssuerAndLifetime(@TempDir Path dir) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        Path keyFile = dir.resolve("client.pem");
        Files.writeString(keyFile, pem("RSA PRIVATE KEY", innerPrivateKey(keyPair.getPrivate().getEncoded())));
        try (EmbeddedServer authServer = authServer()) {
            Map<String, Object> config = privateKeyJwtConfig(authServer);
            config.put(PREFIX + "token.client-assertion.private-key", "file:" + keyFile.toAbsolutePath());
            config.put(PREFIX + "token.client-assertion.lifetime", "30s");
            try (ApplicationContext ctx = ApplicationContext.run(config)) {
                assertTokenResponse(ctx);
                CapturedRequest request = captured(authServer);
                assertPrivateKeyJwtRequest(request);

                SignedJWT jwt = SignedJWT.parse(request.form().get(SecureGrant.KEY_CLIENT_ASSERTION));
                assertEquals("RS256", jwt.getHeader().getAlgorithm().getName());
                assertNull(jwt.getHeader().getKeyID());
                JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) keyPair.getPublic());
                assertTrue(jwt.verify(verifier));
                assertEquals(List.of(ISSUER_IDENTIFIER), jwt.getJWTClaimsSet().getAudience());
                assertEquals(Duration.ofSeconds(30).toMillis(),
                    jwt.getJWTClaimsSet().getExpirationTime().getTime() - jwt.getJWTClaimsSet().getIssueTime().getTime());
            }
        }
    }

    @Test
    void localSigningWithSec1EcKey() throws Exception {
        KeyPair keyPair = ecKeyPair("secp384r1");
        try (EmbeddedServer authServer = authServer()) {
            Map<String, Object> config = privateKeyJwtConfig(authServer);
            config.put(PREFIX + "token.client-assertion.algorithm", "ES384");
            config.put(PREFIX + "token.client-assertion.private-key", pem("EC PRIVATE KEY", innerPrivateKey(keyPair.getPrivate().getEncoded())));
            try (ApplicationContext ctx = ApplicationContext.run(config)) {
                assertTokenResponse(ctx);
                CapturedRequest request = captured(authServer);
                assertPrivateKeyJwtRequest(request);
                SignedJWT jwt = SignedJWT.parse(request.form().get(SecureGrant.KEY_CLIENT_ASSERTION));
                assertTrue(jwt.verify(new ECDSAVerifier((ECPublicKey) keyPair.getPublic())));
            }
        }
    }

    @Test
    void remoteSigningUsesApplicationProvidedGenerator() {
        try (EmbeddedServer authServer = authServer()) {
            Map<String, Object> config = privateKeyJwtConfig(authServer);
            config.put("spec.name", "PrivateKeyJwtRemoteSigning");
            config.put(PREFIX + "token.client-assertion.remote-signing-enabled", true);
            config.put(PREFIX + "token.client-assertion.key-name", "remote-key");
            try (ApplicationContext ctx = ApplicationContext.run(config)) {
                OauthClientConfiguration clientConfiguration = ctx.getBean(OauthClientConfiguration.class, Qualifiers.byName(CLIENT));
                assertEquals("remote-key", clientConfiguration.getToken()
                    .orElseThrow()
                    .getClientAssertion()
                    .orElseThrow()
                    .getKeyName()
                    .orElseThrow());
                Collection<ClientAssertionGenerator> generators = ctx.getBeansOfType(ClientAssertionGenerator.class, Qualifiers.byName(CLIENT));
                assertEquals(1, generators.size());
                assertInstanceOf(RemoteClientAssertionGenerator.class, generators.iterator().next());
                assertTokenResponse(ctx);
                CapturedRequest request = captured(authServer);
                assertPrivateKeyJwtRequest(request);
                assertEquals(REMOTE_ASSERTION, request.form().get(SecureGrant.KEY_CLIENT_ASSERTION));
            }
        }
    }

    @Test
    void openIdIssuerIsUsedAsAudience() throws Exception {
        KeyPair keyPair = ecKeyPair("secp256r1");
        try (EmbeddedServer authServer = authServer()) {
            Map<String, Object> config = privateKeyJwtConfig(authServer);
            config.put(PREFIX + "openid.fetch-configuration", false);
            config.put(PREFIX + "openid.issuer", ISSUER_IDENTIFIER);
            config.put(PREFIX + "openid.token.url", tokenUrl(authServer));
            config.put(PREFIX + "openid.token.authentication-method", AuthenticationMethods.PRIVATE_KEY_JWT);
            config.put(PREFIX + "token.client-assertion.algorithm", "ES256");
            config.put(PREFIX + "token.client-assertion.private-key", pem("PRIVATE KEY", keyPair.getPrivate().getEncoded()));
            try (ApplicationContext ctx = ApplicationContext.run(config)) {
                assertTokenResponse(ctx);
                SignedJWT jwt = SignedJWT.parse(captured(authServer).form().get(SecureGrant.KEY_CLIENT_ASSERTION));
                assertEquals(List.of(ISSUER_IDENTIFIER), jwt.getJWTClaimsSet().getAudience());
                assertTrue(jwt.verify(new ECDSAVerifier((ECPublicKey) keyPair.getPublic())));
            }
        }
    }

    @Test
    void remoteSignerReceivesIssuerIdentifierRatherThanDiscoveryUrl() {
        try (EmbeddedServer authServer = authServer()) {
            Map<String, Object> config = privateKeyJwtConfig(authServer);
            config.remove(PREFIX + "token.client-assertion.audience");
            config.put("spec.name", "PrivateKeyJwtRemoteSigning");
            config.put(PREFIX + "token.client-assertion.remote-signing-enabled", true);
            config.put(PREFIX + "openid.fetch-configuration", false);
            config.put(PREFIX + "openid.issuer", "https://internal.example");
            config.put(PREFIX + "openid.issuer-identifier", ISSUER_IDENTIFIER);
            config.put(PREFIX + "openid.token.url", tokenUrl(authServer));
            config.put(PREFIX + "openid.token.authentication-method", AuthenticationMethods.PRIVATE_KEY_JWT);
            try (ApplicationContext ctx = ApplicationContext.run(config)) {
                assertTokenResponse(ctx);
                assertEquals(REMOTE_ASSERTION, captured(authServer).form().get(SecureGrant.KEY_CLIENT_ASSERTION));
            }
        }
    }

    @Test
    void missingIssuerFailsBeforeSendingRequest() {
        try (EmbeddedServer authServer = authServer()) {
            Map<String, Object> config = privateKeyJwtConfig(authServer);
            config.remove(PREFIX + "token.client-assertion.audience");
            config.put("spec.name", "PrivateKeyJwtRemoteSigning");
            config.put(PREFIX + "token.client-assertion.remote-signing-enabled", true);
            try (ApplicationContext ctx = ApplicationContext.run(config)) {
                ConfigurationException e = assertThrows(ConfigurationException.class, () -> assertTokenResponse(ctx));
                assertTrue(e.getMessage().contains("no issuer identifier is configured"));
                assertNull(authServer.getApplicationContext().getBean(TokenController.class).last);
            }
        }
    }

    @Test
    void blankIssuerFailsBeforeSendingRequest() {
        try (EmbeddedServer authServer = authServer()) {
            Map<String, Object> config = privateKeyJwtConfig(authServer);
            config.put(PREFIX + "token.client-assertion.audience", " ");
            config.put("spec.name", "PrivateKeyJwtRemoteSigning");
            config.put(PREFIX + "token.client-assertion.remote-signing-enabled", true);
            try (ApplicationContext ctx = ApplicationContext.run(config)) {
                ConfigurationException e = assertThrows(ConfigurationException.class, () -> assertTokenResponse(ctx));
                assertTrue(e.getMessage().contains("no issuer identifier is configured"));
                assertNull(authServer.getApplicationContext().getBean(TokenController.class).last);
            }
        }
    }

    @Test
    void audienceConflictingWithOpenIdIssuerFailsBeforeSendingRequest() {
        try (EmbeddedServer authServer = authServer()) {
            Map<String, Object> config = privateKeyJwtConfig(authServer);
            config.put("spec.name", "PrivateKeyJwtRemoteSigning");
            config.put(PREFIX + "token.client-assertion.remote-signing-enabled", true);
            config.put(PREFIX + "openid.fetch-configuration", false);
            config.put(PREFIX + "openid.issuer", ISSUER_IDENTIFIER + "/");
            config.put(PREFIX + "openid.token.url", tokenUrl(authServer));
            config.put(PREFIX + "openid.token.authentication-method", AuthenticationMethods.PRIVATE_KEY_JWT);
            try (ApplicationContext ctx = ApplicationContext.run(config)) {
                ConfigurationException e = assertThrows(ConfigurationException.class, () -> assertTokenResponse(ctx));
                assertTrue(e.getMessage().contains("must match the OpenID issuer identifier"));
                assertNull(authServer.getApplicationContext().getBean(TokenController.class).last);
            }
        }
    }

    @Test
    void localSigningWithoutPrivateKeyFails() {
        Map<String, Object> config = new HashMap<>();
        config.put(PREFIX + "client-id", CLIENT_ID);
        config.put(PREFIX + "token.url", "https://idp.example/token");
        config.put(PREFIX + "token.authentication-method", AuthenticationMethods.PRIVATE_KEY_JWT);
        config.put(PREFIX + "token.client-assertion.algorithm", "RS256");
        try (ApplicationContext ctx = ApplicationContext.run(config)) {
            BeanInstantiationException e = assertThrows(BeanInstantiationException.class,
                () -> ctx.getBean(ClientAssertionGenerator.class, Qualifiers.byName(CLIENT)));
            assertInstanceOf(ConfigurationException.class, rootCause(e));
        }
    }

    @Test
    void invalidPrivateKeyFailsWithoutLeakingKeyMaterial() {
        String invalidKey = "-----BEGIN PRIVATE KEY-----\nbm90LWEta2V5LWZpeHR1cmU=\n-----END PRIVATE KEY-----";
        Map<String, Object> config = new HashMap<>();
        config.put(PREFIX + "client-id", CLIENT_ID);
        config.put(PREFIX + "token.url", "https://idp.example/token");
        config.put(PREFIX + "token.authentication-method", AuthenticationMethods.PRIVATE_KEY_JWT);
        config.put(PREFIX + "token.client-assertion.private-key", invalidKey);
        try (ApplicationContext ctx = ApplicationContext.run(config)) {
            BeanInstantiationException e = assertThrows(BeanInstantiationException.class,
                () -> ctx.getBean(ClientAssertionGenerator.class, Qualifiers.byName(CLIENT)));
            Throwable cause = rootCauseOfType(e);
            assertNotNull(cause);
            assertFalse(cause.getMessage().contains("bm90LWEta2V5LWZpeHR1cmU"));
        }
    }

    @Test
    void unsupportedSigningAlgorithmFailsWithConfigurationError() {
        Map<String, Object> config = new HashMap<>();
        config.put(PREFIX + "client-id", CLIENT_ID);
        config.put(PREFIX + "token.url", "https://idp.example/token");
        config.put(PREFIX + "token.authentication-method", AuthenticationMethods.PRIVATE_KEY_JWT);
        config.put(PREFIX + "token.client-assertion.algorithm", "HS256");
        config.put(PREFIX + "token.client-assertion.private-key", "unused");
        try (ApplicationContext ctx = ApplicationContext.run(config)) {
            BeanInstantiationException e = assertThrows(BeanInstantiationException.class,
                () -> ctx.getBean(ClientAssertionGenerator.class, Qualifiers.byName(CLIENT)));
            Throwable cause = rootCauseOfType(e);
            assertNotNull(cause);
            assertTrue(cause.getMessage().contains("Unsupported client assertion signing algorithm: HS256"));
        }
    }

    @Test
    void clientSecretBasicIsNotAffected() {
        try (EmbeddedServer authServer = authServer()) {
            Map<String, Object> config = new HashMap<>();
            config.put(PREFIX + "client-id", CLIENT_ID);
            config.put(PREFIX + "client-secret", "client-secret-fixture-not-a-secret");
            config.put(PREFIX + "grant-type", "client_credentials");
            config.put(PREFIX + "token.url", tokenUrl(authServer));
            config.put(PREFIX + "token.client-assertion.private-key", "ignored");
            try (ApplicationContext ctx = ApplicationContext.run(config)) {
                assertTrue(ctx.findBean(ClientAssertionGenerator.class, Qualifiers.byName(CLIENT)).isEmpty());
                assertTokenResponse(ctx);
                CapturedRequest request = captured(authServer);
                assertNotNull(request.authorization());
                assertTrue(request.authorization().startsWith("Basic "));
                assertFalse(request.form().containsKey(SecureGrant.KEY_CLIENT_ASSERTION));
                assertFalse(request.form().containsKey(SecureGrant.KEY_CLIENT_ASSERTION_TYPE));
            }
        }
    }

    @Test
    void discoveredPrivateKeyJwtSupportWithoutGeneratorKeepsClientSecretBasic() {
        try (EmbeddedServer authServer = authServer()) {
            Map<String, Object> config = new HashMap<>();
            config.put(PREFIX + "client-id", CLIENT_ID);
            config.put(PREFIX + "client-secret", "client-secret-fixture-not-a-secret");
            try (ApplicationContext ctx = ApplicationContext.run(config)) {
                OauthClientConfiguration clientConfiguration = ctx.getBean(OauthClientConfiguration.class, Qualifiers.byName(CLIENT));
                ClientCredentialsTokenRequestContext requestContext = new ClientCredentialsTokenRequestContext("read",
                    new DefaultSecureEndpoint(tokenUrl(authServer), Set.of(AuthenticationMethods.PRIVATE_KEY_JWT, AuthenticationMethods.CLIENT_SECRET_BASIC)),
                    clientConfiguration);
                TokenResponse response = Mono.from(ctx.getBean(TokenEndpointClient.class).sendRequest(requestContext)).block();
                assertNotNull(response);
                CapturedRequest request = captured(authServer);
                assertNotNull(request.authorization());
                assertTrue(request.authorization().startsWith("Basic "));
                assertFalse(request.form().containsKey(SecureGrant.KEY_CLIENT_ASSERTION));
            }
        }
    }

    @Test
    void privateKeyJwtWithoutGeneratorSendsNoClientAssertion() {
        try (EmbeddedServer authServer = authServer()) {
            Map<String, Object> config = privateKeyJwtConfig(authServer);
            config.put(PREFIX + "token.client-assertion.remote-signing-enabled", true);
            try (ApplicationContext ctx = ApplicationContext.run(config)) {
                assertTrue(ctx.getBeansOfType(ClientAssertionGenerator.class, Qualifiers.byName(CLIENT)).isEmpty());
                assertTokenResponse(ctx);
                CapturedRequest request = captured(authServer);
                assertNull(request.authorization());
                assertEquals(CLIENT_ID, request.form().get(SecureGrant.KEY_CLIENT_ID));
                assertFalse(request.form().containsKey(SecureGrant.KEY_CLIENT_ASSERTION));
                assertFalse(request.form().containsKey(SecureGrant.KEY_CLIENT_SECRET));
            }
        }
    }

    @Test
    void emptyClientAssertionFailsBeforeSendingRequest() {
        try (EmbeddedServer authServer = authServer()) {
            Map<String, Object> config = privateKeyJwtConfig(authServer);
            config.put("spec.name", "PrivateKeyJwtEmptySigning");
            config.put(PREFIX + "token.client-assertion.remote-signing-enabled", true);
            try (ApplicationContext ctx = ApplicationContext.run(config)) {
                IllegalStateException e = assertThrows(IllegalStateException.class, () -> assertTokenResponse(ctx));
                assertTrue(e.getMessage().contains("No client assertion generated"));
                assertNull(authServer.getApplicationContext().getBean(TokenController.class).last);
            }
        }
    }

    @Test
    void grantsExposeClientAssertion() {
        ClientCredentialsGrant grant = new ClientCredentialsGrant();
        grant.setClientId(CLIENT_ID);
        grant.setClientAssertion(REMOTE_ASSERTION);
        grant.setClientAssertionType(ClientAssertionGenerator.JWT_BEARER_ASSERTION_TYPE);
        Map<String, String> map = grant.toMap();
        assertEquals(REMOTE_ASSERTION, map.get(SecureGrant.KEY_CLIENT_ASSERTION));
        assertEquals(ClientAssertionGenerator.JWT_BEARER_ASSERTION_TYPE, map.get(SecureGrant.KEY_CLIENT_ASSERTION_TYPE));
        assertFalse(map.containsKey(SecureGrant.KEY_CLIENT_SECRET));

        SecureGrantMap secureGrantMap = new SecureGrantMap();
        secureGrantMap.setClientAssertion(REMOTE_ASSERTION);
        secureGrantMap.setClientAssertionType(ClientAssertionGenerator.JWT_BEARER_ASSERTION_TYPE);
        assertEquals(REMOTE_ASSERTION, secureGrantMap.get(SecureGrant.KEY_CLIENT_ASSERTION));
        assertEquals(ClientAssertionGenerator.JWT_BEARER_ASSERTION_TYPE, secureGrantMap.get(SecureGrant.KEY_CLIENT_ASSERTION_TYPE));
    }

    private static void assertTokenResponse(ApplicationContext ctx) {
        ClientCredentialsClient client = ctx.getBean(ClientCredentialsClient.class, Qualifiers.byName(CLIENT));
        TokenResponse response = Mono.from(client.requestToken()).block();
        assertNotNull(response);
        assertEquals(ACCESS_TOKEN, response.getAccessToken());
    }

    private static void assertPrivateKeyJwtRequest(CapturedRequest request) {
        assertNull(request.authorization(), "private_key_jwt must not send an Authorization header");
        assertEquals(CLIENT_ID, request.form().get(SecureGrant.KEY_CLIENT_ID));
        assertEquals(ClientAssertionGenerator.JWT_BEARER_ASSERTION_TYPE, request.form().get(SecureGrant.KEY_CLIENT_ASSERTION_TYPE));
        assertNotNull(request.form().get(SecureGrant.KEY_CLIENT_ASSERTION));
        assertFalse(request.form().containsKey(SecureGrant.KEY_CLIENT_SECRET));
    }

    private static EmbeddedServer authServer() {
        return ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", "PrivateKeyJwtAuthServer"));
    }

    private static CapturedRequest captured(EmbeddedServer authServer) {
        CapturedRequest request = authServer.getApplicationContext().getBean(TokenController.class).last;
        assertNotNull(request);
        return request;
    }

    private static String tokenUrl(EmbeddedServer authServer) {
        return authServer.getURL() + "/token";
    }

    private static Map<String, Object> privateKeyJwtConfig(EmbeddedServer authServer) {
        Map<String, Object> config = new HashMap<>();
        config.put(PREFIX + "client-id", CLIENT_ID);
        config.put(PREFIX + "grant-type", "client_credentials");
        config.put(PREFIX + "token.url", tokenUrl(authServer));
        config.put(PREFIX + "token.authentication-method", AuthenticationMethods.PRIVATE_KEY_JWT);
        config.put(PREFIX + "token.client-assertion.audience", ISSUER_IDENTIFIER);
        return config;
    }

    private static KeyPair ecKeyPair(String curve) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(curve));
        return generator.generateKeyPair();
    }

    private static String pem(String type, byte[] der) {
        return "-----BEGIN " + type + "-----\n"
            + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der)
            + "\n-----END " + type + "-----\n";
    }

    /**
     * Extracts the algorithm specific private key (PKCS#1 for RSA, SEC1 for EC) from a PKCS#8 PrivateKeyInfo:
     * SEQUENCE { INTEGER version, SEQUENCE algorithm, OCTET STRING privateKey }.
     */
    private static byte[] innerPrivateKey(byte[] pkcs8) {
        int[] position = {0};
        readHeader(pkcs8, position, 0x30);
        int versionLength = readHeader(pkcs8, position, 0x02);
        position[0] += versionLength;
        int algorithmLength = readHeader(pkcs8, position, 0x30);
        position[0] += algorithmLength;
        int length = readHeader(pkcs8, position, 0x04);
        return Arrays.copyOfRange(pkcs8, position[0], position[0] + length);
    }

    private static int readHeader(byte[] der, int[] position, int tag) {
        assertEquals(tag, der[position[0]++] & 0xFF);
        int first = der[position[0]++] & 0xFF;
        if ((first & 0x80) == 0) {
            return first;
        }
        int count = first & 0x7F;
        byte[] length = Arrays.copyOfRange(der, position[0], position[0] + count);
        position[0] += count;
        return new BigInteger(1, length).intValueExact();
    }

    private static Throwable rootCause(Throwable e) {
        Throwable cause = e;
        while (cause.getCause() != null) {
            cause = cause.getCause();
        }
        return cause;
    }

    private static @Nullable Throwable rootCauseOfType(Throwable e) {
        Throwable cause = e;
        while (cause != null) {
            if (cause instanceof ConfigurationException) {
                return cause;
            }
            cause = cause.getCause();
        }
        return null;
    }

    record CapturedRequest(Map<String, String> form, @Nullable String authorization) {
    }

    @Requires(property = "spec.name", value = "PrivateKeyJwtAuthServer")
    @Controller("/token")
    static class TokenController {
        volatile CapturedRequest last;

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Post
        Map<String, Object> token(@Body Map<String, String> form, @Header(HttpHeaders.AUTHORIZATION) @Nullable String authorization) {
            last = new CapturedRequest(form, authorization);
            return Map.of("access_token", ACCESS_TOKEN, "token_type", "Bearer", "expires_in", 3600);
        }
    }

    @Requires(property = "spec.name", value = "PrivateKeyJwtRemoteSigning")
    @Singleton
    @Named(CLIENT)
    static class RemoteClientAssertionGenerator implements ClientAssertionGenerator {
        @Override
        public @NonNull Publisher<String> generateAssertion(@NonNull String clientId, @NonNull String issuerIdentifier) {
            assertEquals(CLIENT_ID, clientId);
            assertEquals(ISSUER_IDENTIFIER, issuerIdentifier);
            return Mono.just(REMOTE_ASSERTION);
        }
    }

    @Requires(property = "spec.name", value = "PrivateKeyJwtEmptySigning")
    @Singleton
    @Named(CLIENT)
    static class EmptyClientAssertionGenerator implements ClientAssertionGenerator {
        @Override
        public @NonNull Publisher<String> generateAssertion(@NonNull String clientId, @NonNull String issuerIdentifier) {
            return Mono.empty();
        }
    }
}
