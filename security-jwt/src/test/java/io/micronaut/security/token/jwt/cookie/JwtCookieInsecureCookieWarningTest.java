package io.micronaut.security.token.jwt.cookie;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider;
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario;
import io.micronaut.security.token.cookie.CookieLoginHandler;
import io.micronaut.security.token.event.RefreshTokenGeneratedEvent;
import io.micronaut.security.token.refresh.RefreshTokenPersistence;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Property(name = "spec.name", value = "JwtCookieInsecureCookieWarningTest")
@Property(name = "micronaut.http.client.follow-redirects", value = "false")
@Property(name = "micronaut.security.authentication", value = "cookie")
@Property(name = "micronaut.security.redirect.login-failure", value = "/login/authFailed")
@Property(name = "micronaut.security.token.jwt.signatures.secret.generator.secret", value = "qrD6h8K6S9503Q06Y6Rfk21TErImPYqa")
@Property(name = "micronaut.security.token.jwt.generator.refresh-token.secret", value = "pleaseChangeThisSecretForANewOne")
@MicronautTest
class JwtCookieInsecureCookieWarningTest {

    private final Logger logger = (Logger) LoggerFactory.getLogger(CookieLoginHandler.class);
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();

    @BeforeEach
    void attachAppender() {
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void detachAppender() {
        logger.detachAppender(appender);
        appender.stop();
    }

    @Test
    void warnRecommendingCookieSecureIsLoggedOnlyOnceAcrossTwoLoginsOverPlainHttp(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();

        List<String> cookies = client.exchange(loginRequest(), String.class).getHeaders().getAll("Set-Cookie");

        assertEquals(2, cookies.size());
        assertTrue(cookies.stream().noneMatch(cookie -> cookie.contains("Secure")));
        assertEquals(1, warnings().size());
        assertTrue(warnings().get(0).getFormattedMessage().contains("micronaut.security.token.cookie.cookie-secure=true"));

        HttpResponse<String> secondLogin = client.exchange(loginRequest(), String.class);

        assertEquals(2, secondLogin.getHeaders().getAll("Set-Cookie").size());
        assertEquals(1, warnings().size());
    }

    private static HttpRequest<?> loginRequest() {
        return HttpRequest.POST("/login", Map.of("username", "sherlock", "password", "password"))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
    }

    private List<ILoggingEvent> warnings() {
        return appender.list.stream().filter(event -> event.getLevel() == Level.WARN).toList();
    }

    @Requires(property = "spec.name", value = "JwtCookieInsecureCookieWarningTest")
    @Singleton
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super(List.of(new SuccessAuthenticationScenario("sherlock")));
        }
    }

    @Requires(property = "spec.name", value = "JwtCookieInsecureCookieWarningTest")
    @Singleton
    static class InMemoryRefreshTokenPersistence implements RefreshTokenPersistence {

        private final Map<String, Authentication> tokens = new ConcurrentHashMap<>();

        @Override
        public void persistToken(RefreshTokenGeneratedEvent event) {
            tokens.put(event.getRefreshToken(), event.getAuthentication());
        }

        @Override
        public Publisher<Authentication> getAuthentication(String refreshToken) {
            return Publishers.just(tokens.get(refreshToken));
        }
    }
}
