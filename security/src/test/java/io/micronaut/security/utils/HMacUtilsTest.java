package io.micronaut.security.utils;

import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

class HMacUtilsTest {

    @Test
    void testHmacSha256() throws NoSuchAlgorithmException, InvalidKeyException {
        String data = "abcdedf";
        String signatureKey = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
        String hmac = HMacUtils.base64EncodedHmacSha256(data, signatureKey);
        assertNotNull(hmac);
        assertEquals(hmac, HMacUtils.base64EncodedHmacSha256(data, signatureKey));
        assertNotEquals(hmac, HMacUtils.base64EncodedHmacSha256("foobar", signatureKey));
        assertNotEquals(hmac, HMacUtils.base64EncodedHmacSha256(data, signatureKey + "evil"));
    }
}