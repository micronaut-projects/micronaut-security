package io.micronaut.security.token.jwt.signature.jwks;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.security.token.jwt.nimbus.ReactiveJwksSignature;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * {@code micronaut.security.token.jwt.signatures.jwks.*.key-type} restricts the keys used to verify a JWT to the configured key type.
 * If it is not set, keys of any key type are used.
 */
class JwksKeyTypeTest {

    private static RSAKey rsaKey;
    private static ECKey ecKey;
    private static JWKSet jwkSet;

    @BeforeAll
    static void setup() throws Exception {
        rsaKey = new RSAKeyGenerator(2048).keyID("rsa").generate();
        ecKey = new ECKeyGenerator(Curve.P_256).keyID("ec").generate();
        jwkSet = new JWKSet(List.of((JWK) rsaKey.toPublicJWK(), ecKey.toPublicJWK()));
    }

    static Stream<Arguments> keyTypes() {
        return Stream.of(
            // key-type, token signed with the RSA key accepted, token signed with the EC key accepted
            Arguments.of(null, true, true),
            Arguments.of(KeyType.RSA, true, false),
            Arguments.of(KeyType.EC, false, true)
        );
    }

    @ParameterizedTest(name = "key-type {0}")
    @MethodSource("keyTypes")
    void keyTypeRestrictsVerificationKeys(KeyType keyType, boolean rsaAccepted, boolean ecAccepted) throws Exception {
        ReactiveJwksSignature signature = signature(keyType);
        for (boolean withKid : new boolean[] {true, false}) {
            SignedJWT rsaJwt = sign(new RSASSASigner(rsaKey), JWSAlgorithm.RS256, withKid ? rsaKey.getKeyID() : null);
            SignedJWT ecJwt = sign(new ECDSASigner(ecKey), JWSAlgorithm.ES256, withKid ? ecKey.getKeyID() : null);

            assertEquals(rsaAccepted, Mono.from(signature.verify(rsaJwt)).block(), "RSA signed token, kid present: " + withKid);
            assertEquals(ecAccepted, Mono.from(signature.verify(ecJwt)).block(), "EC signed token, kid present: " + withKid);
            assertEquals(rsaAccepted, JwksSignatureUtils.verify(rsaJwt, jwkSet, keyType, new DefaultJwkValidator()));
            assertEquals(ecAccepted, JwksSignatureUtils.verify(ecJwt, jwkSet, keyType, new DefaultJwkValidator()));
        }
    }

    private static ReactiveJwksSignature signature(KeyType keyType) {
        JwksSignatureConfigurationProperties configuration = new JwksSignatureConfigurationProperties("mixed");
        configuration.setUrl("http://localhost/keys");
        configuration.setKeyType(keyType);
        JwkSetFetcher<JWKSet> fetcher = new JwkSetFetcher<>() {
            @Override
            public Publisher<JWKSet> fetch(String providerName, String url) {
                return Mono.just(jwkSet);
            }

            @Override
            public void clearCache(String url) {
            }
        };
        return new ReactiveJwksSignature(configuration, new DefaultJwkValidator(), fetcher);
    }

    private static SignedJWT sign(JWSSigner signer, JWSAlgorithm algorithm, String kid) throws Exception {
        JWSHeader.Builder header = new JWSHeader.Builder(algorithm);
        if (kid != null) {
            header = header.keyID(kid);
        }
        SignedJWT jwt = new SignedJWT(header.build(), new JWTClaimsSet.Builder().subject("sherlock").build());
        jwt.sign(signer);
        return jwt;
    }
}
