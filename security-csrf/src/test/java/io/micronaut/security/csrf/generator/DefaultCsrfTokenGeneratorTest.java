package io.micronaut.security.csrf.generator;

import io.micronaut.http.cookie.SameSite;
import io.micronaut.security.csrf.CsrfConfiguration;
import io.micronaut.security.session.SessionIdResolver;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.temporal.TemporalAmount;
import java.util.Base64;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DefaultCsrfTokenGeneratorTest {

    private static final String SECRET = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
    private static final String NON_ASCII_SESSION_ID = "sesión-ñ-日本";
    private static final String RANDOM_VALUE = "cmFuZG9tLXZhbHVl";

    @Test
    void hmacMessagePayloadEncodesSessionIdAsUtf8() {
        String base64SessionId = Base64.getEncoder().encodeToString(NON_ASCII_SESSION_ID.getBytes(StandardCharsets.UTF_8));
        String expected = base64SessionId.length() + "!" + base64SessionId + "!" + RANDOM_VALUE.length() + "!" + RANDOM_VALUE;

        assertEquals(expected, DefaultCsrfTokenGenerator.hmacMessagePayload(NON_ASCII_SESSION_ID, RANDOM_VALUE));
    }

    @Test
    void hmacWithNonAsciiSessionIdIsCharsetIndependent() throws NoSuchAlgorithmException, InvalidKeyException {
        SessionIdResolver<Object> sessionIdResolver = request -> Optional.of(NON_ASCII_SESSION_ID);
        DefaultCsrfTokenGenerator<Object> generator = new DefaultCsrfTokenGenerator<>(new TestCsrfConfiguration(SECRET), sessionIdResolver);

        String base64SessionId = Base64.getEncoder().encodeToString(NON_ASCII_SESSION_ID.getBytes(StandardCharsets.UTF_8));
        String message = base64SessionId.length() + "!" + base64SessionId + "!" + RANDOM_VALUE.length() + "!" + RANDOM_VALUE;
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        String expected = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(mac.doFinal(message.getBytes(StandardCharsets.UTF_8)));

        // Values precomputed with an explicit UTF-8 Mac; they must not change with the JVM's file.encoding
        assertEquals("24!c2VzacOzbi3DsS3ml6XmnKw=!16!cmFuZG9tLXZhbHVl", message);
        assertEquals("M9wduWkw1SPtVaeh33wSqIvGeDzbjsDpw8Le8ZuHc30", expected);
        assertEquals(expected, generator.hmac(new Object(), RANDOM_VALUE));
    }

    private static final class TestCsrfConfiguration implements CsrfConfiguration {
        private final String secretKey;

        TestCsrfConfiguration(String secretKey) {
            this.secretKey = secretKey;
        }

        @Override
        public int getRandomValueSize() {
            return 16;
        }

        @Override
        public String getSecretKey() {
            return secretKey;
        }

        @Override
        public String getHeaderName() {
            return "X-CSRF-TOKEN";
        }

        @Override
        public String getHttpSessionName() {
            return "csrfToken";
        }

        @Override
        public String getFieldName() {
            return "csrfToken";
        }

        @Override
        public String getCookieName() {
            return "__Host-csrfToken";
        }

        @Override
        public Optional<String> getCookieDomain() {
            return Optional.empty();
        }

        @Override
        public Optional<String> getCookiePath() {
            return Optional.of("/");
        }

        @Override
        public Optional<Boolean> isCookieHttpOnly() {
            return Optional.of(true);
        }

        @Override
        public Optional<Boolean> isCookieSecure() {
            return Optional.of(true);
        }

        @Override
        public Optional<TemporalAmount> getCookieMaxAge() {
            return Optional.empty();
        }

        @Override
        public Optional<SameSite> getCookieSameSite() {
            return Optional.of(SameSite.Strict);
        }
    }
}
