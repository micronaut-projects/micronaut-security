package io.micronaut.security.utils;

import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class HMacUtilsTest {

    @Test
    void nonAsciiDataIsHashedAsUtf8RegardlessOfPlatformCharset() throws NoSuchAlgorithmException, InvalidKeyException {
        String data = "sesión-ñ-日本";
        String signatureKey = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(signatureKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        String expected = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));

        // Value precomputed with an explicit UTF-8 Mac; it must not change with the JVM's file.encoding
        assertEquals("TNeM4CXc8NHBDsnLFxizbFHZSU53x_dQf3qpfSeoL2s", expected);
        assertEquals(expected, HMacUtils.base64EncodedHmacSha256(data, signatureKey));
        assertEquals(expected, HMacUtils.base64EncodedHmac("HmacSHA256", data, signatureKey));
    }

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