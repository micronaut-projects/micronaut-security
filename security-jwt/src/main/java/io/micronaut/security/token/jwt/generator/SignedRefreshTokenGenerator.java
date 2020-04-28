/*
 * Copyright 2017-2020 original authors
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
package io.micronaut.security.token.jwt.generator;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.async.SupplierUtil;
import io.micronaut.security.authentication.UserDetails;
import io.micronaut.security.token.generator.RefreshTokenGenerator;
import io.micronaut.security.token.validator.RefreshTokenValidator;
import io.micronaut.security.token.refresh.RefreshTokenPersistence;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.inject.Singleton;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * The default implementation of {@link RefreshTokenGenerator} and {@link RefreshTokenValidator}
 * that encrypts the token with a secret key and validates a token can be decrypted with
 * the same secret key.
 *
 * @author James Kleeh
 * @since 2.0.0
 */
@Singleton
@Requires(beans = RefreshTokenPersistence.class)
public class SignedRefreshTokenGenerator implements RefreshTokenGenerator, RefreshTokenValidator {

    private static final Logger LOG = LoggerFactory.getLogger(SignedRefreshTokenGenerator.class);

    private final Supplier<Cipher> encryptingCipher;
    private final Supplier<Cipher> decryptingCipher;

    /**
     * @param configuration The refresh token configuration
     */
    public SignedRefreshTokenGenerator(RefreshTokenConfiguration configuration) {
        String secret = configuration.getSecret().orElse(null);
        Supplier<byte[]> secretKey;
        if (secret != null) {
            secretKey = SupplierUtil.memoized(() -> this.generateSecretKey(secret.toCharArray()));
        } else {
            secretKey = () -> {
                if (LOG.isWarnEnabled()) {
                    LOG.warn("Cannot generate a refresh token without a secret. Configure micronaut.security.token.jwt.generator.refresh-token.secret");
                }
                return null;
            };
        }
        // Your vector must be 8 bytes long
        IvParameterSpec iv = new IvParameterSpec(new byte[8]);

        encryptingCipher = SupplierUtil.memoized(() -> {
            byte[] key = secretKey.get();
            if (key != null) {
                try {
                    SecretKey secretKeySpec = new SecretKeySpec(key, "DESede");
                    Cipher encrypt = Cipher.getInstance("DESede/CBC/PKCS5Padding");
                    encrypt.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);
                    return encrypt;
                } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException e) {
                    if (LOG.isWarnEnabled()) {
                        LOG.warn("Failed to initialize the secret key to sign refresh tokens", e);
                    }
                }
            }
            return null;
        });

        decryptingCipher = SupplierUtil.memoized(() -> {
            byte[] key = secretKey.get();
            if (key != null) {
                try {
                    SecretKey secretKeySpec = new SecretKeySpec(key, "DESede");
                    Cipher encrypt = Cipher.getInstance("DESede/CBC/PKCS5Padding");
                    encrypt.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);
                    return encrypt;
                } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException e) {
                    if (LOG.isWarnEnabled()) {
                        LOG.warn("Failed to initialize the secret key to sign refresh tokens", e);
                    }
                }
            }
            return null;
        });

    }

    @Override
    public String createKey(UserDetails userDetails) {
        return UUID.randomUUID().toString();
    }

    @Override
    public Optional<String> generate(UserDetails userDetails, String token) {
        Cipher cipher = encryptingCipher.get();
        if (cipher != null) {
            try {
                byte[] encryptedToken = cipher.doFinal(token.getBytes(UTF_8));
                return Optional.of(new String(Base64.getEncoder().encode(encryptedToken), UTF_8));
            } catch (IllegalBlockSizeException | BadPaddingException e) {
                if (LOG.isWarnEnabled()) {
                    LOG.warn("Failed to sign the refresh token", e);
                }
            }
        }
        return Optional.empty();
    }

    @Override
    public Optional<String> validate(String refreshToken) {
        Cipher cipher = decryptingCipher.get();
        if (cipher != null) {
            byte[] token = Base64.getDecoder().decode(refreshToken);
            try {
                byte[] decrypted = cipher.doFinal(token);
                return Optional.of(new String(decrypted, UTF_8));
            } catch (IllegalBlockSizeException | BadPaddingException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Failed to decrypt a refresh token", e);
                }
            }
        }
        return Optional.empty();
    }

    private byte[] generateSecretKey(char[] secret) {
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            PBEKeySpec spec = new PBEKeySpec(secret, "micronaut".getBytes(), 1000, 192);
            SecretKey tempKey = skf.generateSecret(spec);
            return tempKey.getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("Failed to initialize the secret key to sign refresh tokens", e);
            }
            return null;
        }
    }
}
