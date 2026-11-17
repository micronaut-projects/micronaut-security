package io.micronaut.security.token.cookie;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.config.RedirectConfiguration;
import io.micronaut.security.config.RedirectService;
import io.micronaut.security.token.generator.AccessRefreshTokenGenerator;
import io.micronaut.security.token.generator.AccessTokenConfiguration;
import io.micronaut.security.token.render.AccessRefreshToken;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TokenCookieLoginHandlerInsecureCookieWarningTest {

    private static final Authentication AUTHENTICATION = Authentication.build("sherlock");

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
    void warnsOnceNotPerRequestWhenCookiesAreIssuedWithoutSecureOverInsecureRequest() {
        TokenCookieLoginHandler handler = loginHandler(null);
        HttpRequest<?> request = request(false);

        List<String> cookies = handler.loginSuccess(AUTHENTICATION, request).getHeaders().getAll("Set-Cookie");

        assertEquals(2, cookies.size());
        assertTrue(cookies.stream().noneMatch(cookie -> cookie.contains("Secure")));
        assertTrue(cookies.stream().allMatch(cookie -> cookie.contains("SameSite=Lax")));
        assertEquals(1, warnings().size());
        assertTrue(warnings().get(0).getFormattedMessage().contains("micronaut.security.token.cookie.cookie-secure=true"));

        handler.loginSuccess(AUTHENTICATION, request);

        assertEquals(1, warnings().size());

        handler.loginRefresh(AUTHENTICATION, "refresh", request);

        assertEquals(1, warnings().size());
    }

    @Test
    void doesNotWarnWhenRequestIsSecure() {
        List<String> cookies = loginHandler(null).loginSuccess(AUTHENTICATION, request(true)).getHeaders().getAll("Set-Cookie");

        assertEquals(2, cookies.size());
        assertTrue(cookies.stream().allMatch(cookie -> cookie.contains("Secure")));
        assertTrue(warnings().isEmpty());
    }

    @Test
    void doesNotWarnWhenCookieSecureIsTrueOverInsecureRequest() {
        List<String> cookies = loginHandler(true).loginSuccess(AUTHENTICATION, request(false)).getHeaders().getAll("Set-Cookie");

        assertEquals(2, cookies.size());
        assertTrue(cookies.stream().allMatch(cookie -> cookie.contains("Secure")));
        assertTrue(warnings().isEmpty());
    }

    private List<ILoggingEvent> warnings() {
        return appender.list.stream().filter(event -> event.getLevel() == Level.WARN).toList();
    }

    private static HttpRequest<?> request(boolean secure) {
        HttpRequest<?> request = mock(HttpRequest.class);
        when(request.isSecure()).thenReturn(secure);
        return request;
    }

    private static TokenCookieLoginHandler loginHandler(Boolean cookieSecure) {
        RedirectConfiguration redirectConfiguration = mock(RedirectConfiguration.class);
        when(redirectConfiguration.isEnabled()).thenReturn(false);
        TokenCookieConfigurationProperties accessTokenCookieConfiguration = new TokenCookieConfigurationProperties();
        accessTokenCookieConfiguration.setCookieSecure(cookieSecure);
        RefreshTokenCookieConfigurationProperties refreshTokenCookieConfiguration = new RefreshTokenCookieConfigurationProperties(null);
        refreshTokenCookieConfiguration.setCookieSecure(cookieSecure);
        AccessTokenConfiguration accessTokenConfiguration = mock(AccessTokenConfiguration.class);
        when(accessTokenConfiguration.getExpiration()).thenReturn(3600);
        AccessRefreshToken accessRefreshToken = new AccessRefreshToken("access", "refresh", "Bearer", 3600);
        AccessRefreshTokenGenerator accessRefreshTokenGenerator = mock(AccessRefreshTokenGenerator.class);
        when(accessRefreshTokenGenerator.generate(any(Authentication.class))).thenReturn(Optional.of(accessRefreshToken));
        when(accessRefreshTokenGenerator.generate(anyString(), any(Authentication.class))).thenReturn(Optional.of(accessRefreshToken));
        return new TokenCookieLoginHandler(mock(RedirectService.class),
            redirectConfiguration,
            accessTokenCookieConfiguration,
            refreshTokenCookieConfiguration,
            accessTokenConfiguration,
            accessRefreshTokenGenerator,
            null,
            List.of());
    }
}
