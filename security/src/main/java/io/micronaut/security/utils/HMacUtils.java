/*
 * Copyright 2017-2024 original authors
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
package io.micronaut.security.utils;

import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Utility methods for HMAC.
 * @author Sergio del Amo
 * @since 4.11.0
 */
@Internal
public final class HMacUtils {
    private static final String HMAC_SHA256 = "HmacSHA256";

    private HMacUtils() {
    }

    /**
     *
     * @param data Data
     * @param key Signature Key
     * @return HMAC SHA-256 encoded in Base64
     * @throws NoSuchAlgorithmException if no {@code Provider} supports a {@code MacSpi} implementation for the specified algorithm.
     * @throws  InvalidKeyException if the given key is inappropriate for initializing this MAC.
     */
    public static String base64EncodedHmacSha256(@NonNull String data, @NonNull String key) throws NoSuchAlgorithmException, InvalidKeyException {
        return base64EncodedHmac(HMAC_SHA256, data, key);
    }

    /**
     *
     * @param algorithm HMAC algorithm
     * @param data Data
     * @param key Signature Key
     * @return HMAC encoded in Base64
     * @throws NoSuchAlgorithmException if no {@code Provider} supports a {@code MacSpi} implementation for the specified algorithm.
     * @throws  InvalidKeyException if the given key is inappropriate for initializing this MAC.
     */
    public static String base64EncodedHmac(@NonNull String algorithm, @NonNull String data, @NonNull String key)
            throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), algorithm);
        Mac mac = Mac.getInstance(algorithm);
        mac.init(secretKeySpec);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(data.getBytes()));
    }
}
