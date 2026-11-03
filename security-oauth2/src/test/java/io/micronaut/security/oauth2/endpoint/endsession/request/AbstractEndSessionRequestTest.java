package io.micronaut.security.oauth2.endpoint.endsession.request;

import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.simple.SimpleHttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.endsession.response.EndSessionCallbackUrlBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.net.URI;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AbstractEndSessionRequestTest {

    private static final String CALLBACK = "http://localhost:8080/logout";
    private static final String ENCODED_CALLBACK = "http%3A%2F%2Flocalhost%3A8080%2Flogout";
    private static final String FAKE_ID_TOKEN = "header.payload.signature-test-fixture-not-a-secret";

    @Test
    void parametersAreAppendedAsQueryString() {
        String url = url("https://provider.example/logout", Collections.singletonMap("post_logout_redirect_uri", CALLBACK));
        assertEquals("https://provider.example/logout?post_logout_redirect_uri=" + ENCODED_CALLBACK, url);
    }

    @Test
    void parametersArePreservedInInsertionOrderAndEncoded() {
        Map<String, Object> arguments = new LinkedHashMap<>();
        arguments.put("id_token_hint", FAKE_ID_TOKEN);
        arguments.put("post_logout_redirect_uri", CALLBACK);
        arguments.put("client_id", "client id&with=reserved");
        String url = url("https://provider.example/oauth2/v1/logout", arguments);
        assertEquals("https://provider.example/oauth2/v1/logout"
            + "?id_token_hint=" + FAKE_ID_TOKEN
            + "&post_logout_redirect_uri=" + ENCODED_CALLBACK
            + "&client_id=client+id%26with%3Dreserved", url);
    }

    @Test
    void existingQueryComponentOfEndSessionUrlIsKept() {
        String url = url("https://provider.example/logout?tenant=acme", Collections.singletonMap("post_logout_redirect_uri", CALLBACK));
        assertEquals("https://provider.example/logout?tenant=acme&post_logout_redirect_uri=" + ENCODED_CALLBACK, url);
        URI uri = URI.create(url);
        assertEquals("tenant=acme&post_logout_redirect_uri=" + ENCODED_CALLBACK, uri.getRawQuery());
    }

    @Test
    void nullArgumentsAreSkipped() {
        Map<String, Object> arguments = new LinkedHashMap<>();
        arguments.put("id_token_hint", null);
        arguments.put("post_logout_redirect_uri", CALLBACK);
        String url = url("https://provider.example/logout", arguments);
        assertEquals("https://provider.example/logout?post_logout_redirect_uri=" + ENCODED_CALLBACK, url);
    }

    @Test
    void multiValuedArgumentsAreRepeated() {
        String url = url("https://provider.example/logout", Collections.singletonMap("ui_locales", Arrays.asList("en", "es")));
        assertEquals("https://provider.example/logout?ui_locales=en&ui_locales=es", url);
    }

    @Test
    void templateSyntaxInArgumentValuesIsEncodedNotExpanded() {
        String url = url("https://provider.example/logout", Collections.singletonMap("post_logout_redirect_uri", "{parameters}{parameters*}"));
        assertEquals("https://provider.example/logout?post_logout_redirect_uri=%7Bparameters%7D%7Bparameters*%7D", url);
    }

    @Test
    @Timeout(5)
    void endSessionUrlIsNotExpandedAsUriTemplate() {
        // A malicious or compromised provider repeats the nested variable in its end_session_endpoint
        String endSessionEndpoint = "https://provider.example/logout" + repeat("{parameters}", 2000);
        String url = url(endSessionEndpoint, Collections.singletonMap("post_logout_redirect_uri", CALLBACK));
        assertNull(url, "an end session URL that is not a valid URI must not produce a redirect");
    }

    @Test
    @Timeout(5)
    void endSessionUrlWithExplodedQueryTemplateIsRejected() {
        String endSessionEndpoint = "https://provider.example/logout" + repeat("{?parameters*}", 200);
        String url = url(endSessionEndpoint, Collections.singletonMap("post_logout_redirect_uri", CALLBACK));
        assertNull(url);
    }

    @Test
    void templateSyntaxInEndSessionUrlQueryIsEncodedNotExpanded() {
        String url = url("https://provider.example/logout?next={parameters}", Collections.singletonMap("post_logout_redirect_uri", CALLBACK));
        assertEquals("https://provider.example/logout?next=%7Bparameters%7D&post_logout_redirect_uri=" + ENCODED_CALLBACK, url);
    }

    @Test
    void missingEndSessionUrlYieldsNoRedirect() {
        assertNull(url(null, Collections.singletonMap("post_logout_redirect_uri", CALLBACK)));
        assertNull(url("", Collections.singletonMap("post_logout_redirect_uri", CALLBACK)));
    }

    @Test
    void endSessionUrlWithUserInfoIsRejected() {
        // Micronaut's UriBuilder splits the user info on ':' and fails on an empty password; the URL must be
        // rejected before it reaches the builder instead of surfacing as an uncaught exception
        assertNull(url("https://user:@provider.example/logout", Collections.singletonMap("post_logout_redirect_uri", CALLBACK)));
        assertNull(url("https://user:password@provider.example/logout", Collections.singletonMap("post_logout_redirect_uri", CALLBACK)));
        assertNull(url("https://user@provider.example/logout?tenant=acme", Collections.singletonMap("post_logout_redirect_uri", CALLBACK)));
    }

    @Test
    void endSessionUrlMustBeAbsoluteHttpUrlWithHost() {
        Map<String, Object> arguments = Collections.singletonMap("post_logout_redirect_uri", CALLBACK);
        // scheme-relative and relative URLs would be resolved by the browser against this application
        assertNull(url("//user:@evil.example/logout", arguments));
        assertNull(url("//provider.example/logout", arguments));
        assertNull(url("/logout", arguments));
        assertNull(url("logout", arguments));
        // other schemes
        assertNull(url("javascript:alert(1)", arguments));
        assertNull(url("mailto:user@provider.example", arguments));
        assertNull(url("ftp://provider.example/logout", arguments));
        // missing or invalid host
        assertNull(url("https://", arguments));
        assertNull(url("https:///logout", arguments));
        assertNull(url("https://provider.example\\@evil.example/logout", arguments));
        assertNull(url("https://пример.example/logout", arguments));
        // accepted forms
        assertEquals("http://localhost:8180/realms/acme/protocol/openid-connect/logout?post_logout_redirect_uri=" + ENCODED_CALLBACK,
            url("http://localhost:8180/realms/acme/protocol/openid-connect/logout", arguments));
        assertEquals("HTTPS://provider.example/logout?post_logout_redirect_uri=" + ENCODED_CALLBACK,
            url("HTTPS://provider.example/logout", arguments));
        assertEquals("https://[::1]:8443/logout?post_logout_redirect_uri=" + ENCODED_CALLBACK,
            url("https://[::1]:8443/logout", arguments));
        assertEquals("https://provider.example:8443/logout?post_logout_redirect_uri=" + ENCODED_CALLBACK,
            url("https://provider.example:8443/logout", arguments));
    }

    @Test
    void atSignOutsideTheAuthorityIsNotUserInfo() {
        String url = url("https://provider.example/logout?next=user@example", Collections.singletonMap("post_logout_redirect_uri", CALLBACK));
        assertEquals("https://provider.example/logout?next=user%40example&post_logout_redirect_uri=" + ENCODED_CALLBACK, url);
    }

    @Test
    void exceptionFromGetArgumentsIsNotSwallowed() {
        assertThrows(IllegalArgumentException.class, () -> url("https://provider.example/logout", () -> {
            throw new IllegalArgumentException("bad host header");
        }));
    }

    @Test
    void logOfInvalidEndSessionUrlIsTruncated() {
        ch.qos.logback.classic.Logger logger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(AbstractEndSessionRequest.class);
        ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent> appender = new ch.qos.logback.core.read.ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            String endSessionEndpoint = "https://provider.example/logout" + repeat("{x}", 10_000);
            assertNull(url(endSessionEndpoint, Collections.singletonMap("a", "b")));
            assertEquals(1, appender.list.size());
            String message = appender.list.get(0).getFormattedMessage();
            assertTrue(message.length() < 500, message.length() + " characters logged");
            assertTrue(message.contains("30031 characters"));
        } finally {
            logger.detachAppender(appender);
        }
    }

    private static String url(String endSessionEndpoint, Map<String, Object> arguments) {
        return url(endSessionEndpoint, () -> arguments);
    }

    private static String url(String endSessionEndpoint, Supplier<Map<String, Object>> arguments) {
        EndSessionCallbackUrlBuilder callbackUrlBuilder = originating -> {
            try {
                return new URL(CALLBACK);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        };
        Supplier<OpenIdProviderMetadata> metadata = () -> null;
        AbstractEndSessionRequest request = new AbstractEndSessionRequest(callbackUrlBuilder, (OauthClientConfiguration) null, metadata) {
            @Override
            protected String getUrl() {
                return endSessionEndpoint;
            }

            @Override
            protected Map<String, Object> getArguments(HttpRequest<?> originating, Authentication authentication) {
                return arguments.get();
            }
        };
        HttpRequest<?> originating = new SimpleHttpRequest<>(HttpMethod.GET, "/oauth/logout", Collections.emptyMap());
        return request.getUrl(originating, Authentication.build("sherlock"));
    }

    private static String repeat(String s, int times) {
        StringBuilder sb = new StringBuilder(s.length() * times);
        for (int i = 0; i < times; i++) {
            sb.append(s);
        }
        return sb.toString();
    }

}
