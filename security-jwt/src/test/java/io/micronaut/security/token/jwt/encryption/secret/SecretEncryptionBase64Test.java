package io.micronaut.security.token.jwt.encryption.secret;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

class SecretEncryptionBase64Test {

    // Configuration secrets are not request data: routing them through Base64Utils is defence in depth.
    @Test
    void base64SecretWithPaddingThatDoesNotCompleteTheFinalUnitIsRejected() {
        SecretEncryptionConfiguration config = new SecretEncryptionConfiguration("generator");
        config.setJweAlgorithm(JWEAlgorithm.DIR);
        config.setEncryptionMethod(EncryptionMethod.A128GCM);
        config.setSecret("A".repeat(64) + "=");
        config.setBase64(true);

        assertThrows(IllegalArgumentException.class, () -> new SecretEncryption(config));
    }
}
