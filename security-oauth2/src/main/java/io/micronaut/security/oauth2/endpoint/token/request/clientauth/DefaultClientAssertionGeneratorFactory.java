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
package io.micronaut.security.oauth2.endpoint.token.request.clientauth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.context.exceptions.DisabledBeanException;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.io.ResourceResolver;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.ClientAssertionConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.SecureEndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.AuthenticationMethods;
import org.jspecify.annotations.Nullable;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

/**
 * Creates a {@link ClientAssertionGenerator} for each OAuth 2.0 client configured with the {@code private_key_jwt}
 * authentication method and a local PEM-encoded private key ({@code token.client-assertion.private-key}).
 *
 * <p>No generator is created when {@code token.client-assertion.remote-signing-enabled} is {@code true}. In that case,
 * the application provides a {@link ClientAssertionGenerator} bean named after the client.</p>
 *
 * @since 5.5.3
 */
@Internal
@Factory
@Requires(classes = SignedJWT.class)
public class DefaultClientAssertionGeneratorFactory {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultClientAssertionGeneratorFactory.class);
    private static final String CLASSPATH_PREFIX = "classpath:";
    private static final String FILE_PREFIX = "file:";
    private static final String PKCS8_HEADER = "-----BEGIN PRIVATE KEY-----";
    private static final String PKCS1_RSA_HEADER = "-----BEGIN RSA PRIVATE KEY-----";
    private static final String SEC1_EC_HEADER = "-----BEGIN EC PRIVATE KEY-----";
    private static final int DER_SEQUENCE = 0x30;
    private static final int DER_INTEGER = 0x02;
    private static final int DER_OCTET_STRING = 0x04;

    private final ResourceResolver resourceResolver;

    /**
     * @param resourceResolver The resource resolver used to load the private key from a {@code classpath:} or {@code file:} resource
     */
    public DefaultClientAssertionGeneratorFactory(ResourceResolver resourceResolver) {
        this.resourceResolver = resourceResolver;
    }

    /**
     * @param clientConfiguration The OAuth 2.0 client configuration
     * @return A client assertion generator signing with the configured local private key
     */
    @EachBean(OauthClientConfiguration.class)
    ClientAssertionGenerator clientAssertionGenerator(@Parameter OauthClientConfiguration clientConfiguration) {
        String clientName = clientConfiguration.getName();
        String authMethod = clientConfiguration.getToken()
            .flatMap(SecureEndpointConfiguration::getAuthenticationMethod)
            .orElse(null);
        if (!AuthenticationMethods.PRIVATE_KEY_JWT.equals(authMethod)) {
            throw new DisabledBeanException("OAuth client '" + clientName + "' does not use private_key_jwt authentication");
        }
        ClientAssertionConfiguration config = clientConfiguration.getToken()
            .flatMap(SecureEndpointConfiguration::getClientAssertion)
            .orElseThrow(() -> new DisabledBeanException("OAuth client '" + clientName + "' uses private_key_jwt but has no client-assertion configuration"));
        if (config.isRemoteSigningEnabled()) {
            throw new DisabledBeanException("OAuth client '" + clientName + "' uses remote signing for the client assertion");
        }
        String privateKey = config.getPrivateKey()
            .filter(key -> !key.isBlank())
            .orElseThrow(() -> new ConfigurationException("OAuth client '" + clientName + "' uses private_key_jwt with local signing but no client-assertion.private-key is configured"));
        String algorithm = config.getAlgorithm();
        JWSSigner signer;
        try {
            signer = createSigner(loadPemContent(privateKey), algorithm);
        } catch (GeneralSecurityException | JOSEException | IOException | IllegalArgumentException | ClassCastException e) {
            throw new ConfigurationException("Failed to create the client assertion signer of OAuth client '" + clientName + "': " + e.getMessage(), e);
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Created a ClientAssertionGenerator for OAuth client '{}' signing with a local private key", clientName);
        }
        return new DefaultClientAssertionGenerator(signer,
            JWSAlgorithm.parse(algorithm),
            config.getKeyId().orElse(null),
            config.getLifetime());
    }

    private static JWSSigner createSigner(String pemContent, String algorithm) throws GeneralSecurityException, JOSEException {
        if (isRsa(algorithm)) {
            return new RSASSASigner(parsePrivateKey(pemContent, algorithm));
        } else if (algorithm.startsWith("ES")) {
            return new ECDSASigner((ECPrivateKey) parsePrivateKey(pemContent, algorithm));
        }
        throw new IllegalArgumentException("Unsupported client assertion signing algorithm: " + algorithm);
    }

    private static boolean isRsa(String algorithm) {
        return algorithm.startsWith("RS") || algorithm.startsWith("PS");
    }

    private String loadPemContent(String privateKeyConfig) throws IOException {
        if (!privateKeyConfig.startsWith(CLASSPATH_PREFIX) && !privateKeyConfig.startsWith(FILE_PREFIX)) {
            return privateKeyConfig;
        }
        InputStream stream = resourceResolver.getResourceAsStream(privateKeyConfig)
            .orElseThrow(() -> new IOException("Private key resource not found: " + privateKeyConfig));
        try (stream) {
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static PrivateKey parsePrivateKey(String pemContent, String algorithm) throws GeneralSecurityException {
        String pem = pemContent.trim();
        if (pem.contains(PKCS8_HEADER)) {
            KeyFactory keyFactory = KeyFactory.getInstance(isRsa(algorithm) ? "RSA" : "EC");
            return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodePem(pem)));
        }
        if (pem.contains(PKCS1_RSA_HEADER)) {
            return parsePkcs1RsaPrivateKey(decodePem(pem));
        }
        if (pem.contains(SEC1_EC_HEADER)) {
            return parseSec1EcPrivateKey(decodePem(pem), algorithm);
        }
        throw new IllegalArgumentException("Unsupported PEM private key format. Supported formats are PKCS#8, PKCS#1 (RSA) and SEC1 (EC)");
    }

    /**
     * Parses an RFC 8017 {@code RSAPrivateKey} structure: version, n, e, d, p, q, dP, dQ, qInv.
     */
    private static RSAPrivateKey parsePkcs1RsaPrivateKey(byte[] der) throws GeneralSecurityException {
        DerReader reader = new DerReader(der);
        reader.expectTag(DER_SEQUENCE);
        reader.readLength();
        reader.readPositiveInteger();
        BigInteger modulus = reader.readPositiveInteger();
        BigInteger publicExponent = reader.readPositiveInteger();
        BigInteger privateExponent = reader.readPositiveInteger();
        BigInteger primeP = reader.readPositiveInteger();
        BigInteger primeQ = reader.readPositiveInteger();
        BigInteger primeExponentP = reader.readPositiveInteger();
        BigInteger primeExponentQ = reader.readPositiveInteger();
        BigInteger crtCoefficient = reader.readPositiveInteger();
        return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateCrtKeySpec(
            modulus, publicExponent, privateExponent, primeP, primeQ, primeExponentP, primeExponentQ, crtCoefficient));
    }

    /**
     * Parses an RFC 5915 {@code ECPrivateKey} structure: version, privateKey. The curve is derived from the algorithm.
     */
    private static ECPrivateKey parseSec1EcPrivateKey(byte[] der, String algorithm) throws GeneralSecurityException {
        DerReader reader = new DerReader(der);
        reader.expectTag(DER_SEQUENCE);
        reader.readLength();
        reader.readPositiveInteger();
        byte[] privateKey = reader.readOctetString();
        return (ECPrivateKey) KeyFactory.getInstance("EC").generatePrivate(
            new ECPrivateKeySpec(new BigInteger(1, privateKey), ecParameterSpec(algorithm)));
    }

    private static ECParameterSpec ecParameterSpec(String algorithm) throws GeneralSecurityException {
        String curveName = switch (algorithm) {
            case "ES256" -> "secp256r1";
            case "ES384" -> "secp384r1";
            case "ES512" -> "secp521r1";
            case "ES256K" -> "secp256k1";
            default -> throw new IllegalArgumentException("Unsupported EC signing algorithm: " + algorithm);
        };
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec(curveName));
        return parameters.getParameterSpec(ECParameterSpec.class);
    }

    private static byte[] decodePem(String pem) {
        String base64 = pem.replaceAll("-----(BEGIN|END) [A-Z ]*PRIVATE KEY-----", "")
            .replaceAll("\\s", "");
        return Base64.getDecoder().decode(base64);
    }

    /**
     * Minimal DER reader supporting the elements of PKCS#1 and SEC1 private keys.
     */
    private static final class DerReader {
        private final byte[] data;
        private int position;

        private DerReader(byte[] data) {
            this.data = data;
        }

        private void expectTag(int expectedTag) {
            int actualTag = readByte();
            if (actualTag != expectedTag) {
                throw new IllegalArgumentException("Expected DER tag 0x" + Integer.toHexString(expectedTag)
                    + " but found 0x" + Integer.toHexString(actualTag));
            }
        }

        private int readByte() {
            if (position >= data.length) {
                throw new IllegalArgumentException("Unexpected end of DER data");
            }
            return data[position++] & 0xFF;
        }

        private int readLength() {
            int first = readByte();
            if ((first & 0x80) == 0) {
                return first;
            }
            int count = first & 0x7F;
            if (count == 0 || count > 4) {
                throw new IllegalArgumentException("Unsupported DER length encoding");
            }
            int length = 0;
            for (int i = 0; i < count; i++) {
                length = (length << 8) | readByte();
            }
            return length;
        }

        private byte[] readValue(int tag) {
            expectTag(tag);
            int length = readLength();
            if (length < 0 || length > data.length - position) {
                throw new IllegalArgumentException("Invalid DER length");
            }
            byte[] value = new byte[length];
            System.arraycopy(data, position, value, 0, length);
            position += length;
            return value;
        }

        private BigInteger readPositiveInteger() {
            return new BigInteger(1, readValue(DER_INTEGER));
        }

        private byte[] readOctetString() {
            return readValue(DER_OCTET_STRING);
        }
    }

    /**
     * {@link ClientAssertionGenerator} signing the client assertion with Nimbus JOSE + JWT.
     *
     * @param signer The JWS signer
     * @param algorithm The JWS algorithm
     * @param keyId The {@code kid} header value
     * @param lifetime The client assertion lifetime
     */
    private record DefaultClientAssertionGenerator(JWSSigner signer,
                                                   JWSAlgorithm algorithm,
                                                   @Nullable String keyId,
                                                   Duration lifetime) implements ClientAssertionGenerator {

        @Override
        public Publisher<String> generateAssertion(String clientId, String issuerIdentifier) {
            return Mono.fromCallable(() -> {
                Instant now = Instant.now();
                JWSHeader.Builder header = new JWSHeader.Builder(algorithm);
                if (keyId != null) {
                    header.keyID(keyId);
                }
                JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(clientId)
                    .subject(clientId)
                    .audience(issuerIdentifier)
                    .jwtID(UUID.randomUUID().toString())
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plus(lifetime)))
                    .build();
                SignedJWT signedJWT = new SignedJWT(header.build(), claims);
                signedJWT.sign(signer);
                return signedJWT.serialize();
            });
        }
    }
}
