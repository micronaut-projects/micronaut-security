package io.micronaut.security.password.tck.pbkdf2;

import io.micronaut.security.password.PasswordEncoder;
import jakarta.inject.Singleton;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Reference encoder used to run the TCK against an implementation that is independent of the
 * modules shipped by Micronaut Security. It is a test fixture: the iteration count is far too low
 * for production use.
 */
@Singleton
class Pbkdf2PasswordEncoder implements PasswordEncoder {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String SEPARATOR = ":";
    private static final int ITERATIONS = 1_000;
    private static final int SALT_LENGTH = 16;
    private static final int HASH_LENGTH_BITS = 256;

    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    public String encode(String rawPassword) {
        if (rawPassword.isBlank()) {
            throw new IllegalArgumentException("The raw password must not be blank");
        }
        byte[] salt = new byte[SALT_LENGTH];
        secureRandom.nextBytes(salt);
        Base64.Encoder encoder = Base64.getEncoder().withoutPadding();
        return ITERATIONS + SEPARATOR + encoder.encodeToString(salt) + SEPARATOR + encoder.encodeToString(hash(rawPassword, salt, ITERATIONS));
    }

    @Override
    public boolean matches(String rawPassword, String encodedPassword) {
        if (rawPassword.isBlank()) {
            return false;
        }
        String[] parts = encodedPassword.split(SEPARATOR, -1);
        if (parts.length != 3) {
            return false;
        }
        try {
            int iterations = Integer.parseInt(parts[0]);
            byte[] salt = Base64.getDecoder().decode(parts[1]);
            byte[] expected = Base64.getDecoder().decode(parts[2]);
            if (salt.length != SALT_LENGTH || expected.length != HASH_LENGTH_BITS / Byte.SIZE) {
                return false;
            }
            return MessageDigest.isEqual(expected, hash(rawPassword, salt, iterations));
        } catch (IllegalArgumentException _) {
            return false;
        }
    }

    private static byte[] hash(String rawPassword, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(rawPassword.toCharArray(), salt, iterations, HASH_LENGTH_BITS);
        try {
            return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        } finally {
            spec.clearPassword();
        }
    }
}
