package io.micronaut.security.oauth2.endpoint.token.response;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.config.RedirectConfiguration;
import io.micronaut.security.config.RedirectService;
import io.micronaut.security.token.cookie.CookieLoginHandler;
import io.micronaut.security.token.cookie.TokenCookieConfigurationProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class IdTokenLoginHandlerInsecureCookieWarningTest {

    private static final Authentication AUTHENTICATION = Authentication.build("sherlock",
        Map.of(OpenIdAuthenticationMapper.OPENID_TOKEN_KEY, "idtoken"));

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
    void warnsOnceWhenIdTokenCookieIsIssuedWithoutSecureOverInsecureRequest() {
        IdTokenLoginHandler handler = loginHandler(null);
        HttpRequest<?> request = request(false);

        List<Cookie> cookies = handler.getCookies(AUTHENTICATION, request);

        assertEquals(1, cookies.size());
        assertFalse(cookies.get(0).isSecure());
        assertEquals(1, warnings().size());
        assertTrue(warnings().get(0).getFormattedMessage().contains("micronaut.security.token.cookie.cookie-secure=true"));

        handler.getCookies(AUTHENTICATION, request);

        assertEquals(1, warnings().size());
    }

    @Test
    void doesNotWarnWhenRequestIsSecure() {
        List<Cookie> cookies = loginHandler(null).getCookies(AUTHENTICATION, request(true));

        assertTrue(cookies.get(0).isSecure());
        assertTrue(warnings().isEmpty());
    }

    @Test
    void doesNotWarnWhenCookieSecureIsTrueOverInsecureRequest() {
        List<Cookie> cookies = loginHandler(true).getCookies(AUTHENTICATION, request(false));

        assertTrue(cookies.get(0).isSecure());
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

    private static IdTokenLoginHandler loginHandler(Boolean cookieSecure) {
        RedirectConfiguration redirectConfiguration = mock(RedirectConfiguration.class);
        when(redirectConfiguration.isEnabled()).thenReturn(false);
        TokenCookieConfigurationProperties configuration = new TokenCookieConfigurationProperties();
        configuration.setCookieSecure(cookieSecure);
        configuration.setSessionCookie(true);
        return new IdTokenLoginHandler(configuration, redirectConfiguration, mock(RedirectService.class), null, List.of());
    }
}
