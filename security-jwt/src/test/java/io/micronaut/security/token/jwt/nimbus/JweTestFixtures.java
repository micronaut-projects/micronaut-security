package io.micronaut.security.token.jwt.nimbus;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.nio.charset.StandardCharsets;

/**
 * Tokens and secrets shared by the {@link NimbusJsonWebTokenParser} JWE tests.
 */
final class JweTestFixtures {
    static final String SIGNATURE_SECRET = "pleaseChangeThisSecretForANewOne";
    static final String ENCRYPTION_SECRET = "anEncryptionSecretOf32Characters";
    static final String OTHER_ENCRYPTION_SECRET = "thisIsADifferentSecretOfLength32";
    static final String SUBJECT = "1234567890";

    private JweTestFixtures() {
    }

    static JWTClaimsSet claimsSet() {
        return new JWTClaimsSet.Builder()
            .subject(SUBJECT)
            .claim("name", "John Doe")
            .build();
    }

    /**
     * @return a JWT signed with {@link #SIGNATURE_SECRET}
     */
    static SignedJWT signedJwt() throws JOSEException {
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet());
        signedJWT.sign(new MACSigner(SIGNATURE_SECRET.getBytes(StandardCharsets.UTF_8)));
        return signedJWT;
    }

    /**
     * @return a serialized JWE whose payload is the claims set, not a nested signed JWT
     */
    static String plainJwe(String encryptionSecret) throws JOSEException {
        EncryptedJWT encryptedJWT = new EncryptedJWT(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM), claimsSet());
        encryptedJWT.encrypt(new DirectEncrypter(encryptionSecret.getBytes(StandardCharsets.UTF_8)));
        return encryptedJWT.serialize();
    }

    /**
     * @return a serialized JWE whose payload is a nested signed JWT
     */
    static String nestedJwe(String encryptionSecret) throws JOSEException {
        JWEObject jweObject = new JWEObject(
            new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM).contentType("JWT").build(),
            new Payload(signedJwt()));
        jweObject.encrypt(new DirectEncrypter(encryptionSecret.getBytes(StandardCharsets.UTF_8)));
        return jweObject.serialize();
    }
}
