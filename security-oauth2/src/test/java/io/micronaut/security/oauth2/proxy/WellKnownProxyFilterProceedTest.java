package io.micronaut.security.oauth2.proxy;

import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.client.ProxyHttpClient;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

class WellKnownProxyFilterProceedTest {

    @Test
    void proceed_isFalse_forOpenIdConfiguration_whenProxyEnabled() throws MalformedURLException {
        WellKnownProxyFilter filter = newFilter(false, true);
        HttpRequest<?> request = mock(HttpRequest.class);
        when(request.getMethod()).thenReturn(HttpMethod.GET);
        when(request.getPath()).thenReturn(WellKnownProxyFilter.OPENID_CONFIGURATION_PATH);

        boolean result = filter.proceed(request);

        assertFalse(result, "Expected proceed=false to proxy openid-configuration when enabled");
    }

    @Test
    void proceed_isFalse_forOauthAuthorizationServer_whenProxyEnabled() throws MalformedURLException {
        WellKnownProxyFilter filter = newFilter(true, false);
        HttpRequest<?> request = mock(HttpRequest.class);
        when(request.getMethod()).thenReturn(HttpMethod.GET);
        when(request.getPath()).thenReturn(WellKnownProxyFilter.OAUTH_AUTHORIZATION_SERVER_WELL_KNOWN_PATH);

        boolean result = filter.proceed(request);

        assertFalse(result, "Expected proceed=false to proxy oauth-authorization-server when enabled");
    }

    @Test
    void proceed_isTrue_forOpenIdConfiguration_whenProxyDisabled() throws MalformedURLException {
        WellKnownProxyFilter filter = newFilter(false, false);
        HttpRequest<?> request = mock(HttpRequest.class);
        when(request.getMethod()).thenReturn(HttpMethod.GET);
        when(request.getPath()).thenReturn(WellKnownProxyFilter.OPENID_CONFIGURATION_PATH);

        boolean result = filter.proceed(request);

        assertTrue(result, "Expected proceed=true when openid-configuration proxy is disabled");
    }

    @Test
    void proceed_isTrue_forOauthAuthorizationServer_whenProxyDisabled() throws MalformedURLException {
        WellKnownProxyFilter filter = newFilter(false, false);
        HttpRequest<?> request = mock(HttpRequest.class);
        when(request.getMethod()).thenReturn(HttpMethod.GET);
        when(request.getPath()).thenReturn(WellKnownProxyFilter.OAUTH_AUTHORIZATION_SERVER_WELL_KNOWN_PATH);

        boolean result = filter.proceed(request);

        assertTrue(result, "Expected proceed=true when oauth-authorization-server proxy is disabled");
    }

    @Test
    void proceed_isTrue_whenMethodNotGET() throws MalformedURLException {
        WellKnownProxyFilter filter = newFilter(true, true);
        HttpRequest<?> request = mock(HttpRequest.class);
        when(request.getMethod()).thenReturn(HttpMethod.POST);
        when(request.getPath()).thenReturn(WellKnownProxyFilter.OPENID_CONFIGURATION_PATH);

        boolean result = filter.proceed(request);

        assertTrue(result, "Expected proceed=true for non-GET methods");
    }

    @Test
    void proceed_isTrue_whenSettingsNull() {
        ProxyHttpClient proxyHttpClient = mock(ProxyHttpClient.class);
        WellKnownProxyFilter filter = new WellKnownProxyFilter(Collections.emptyList(), proxyHttpClient);
        HttpRequest<?> request = mock(HttpRequest.class);
        when(request.getMethod()).thenReturn(HttpMethod.GET);
        when(request.getPath()).thenReturn(WellKnownProxyFilter.OPENID_CONFIGURATION_PATH);

        boolean result = filter.proceed(request);

        assertTrue(result, "Expected proceed=true when settings are null");
    }

    private WellKnownProxyFilter newFilter(boolean proxyOauthAuthorizationServer, boolean proxyOpenIdConfiguration) throws MalformedURLException {
        OauthClientConfiguration cfg = mock(OauthClientConfiguration.class);
        when(cfg.isProxyWellKnownOauthAuthorizationServer()).thenReturn(proxyOauthAuthorizationServer);
        when(cfg.isProxyWellKnownOpenidConfiguration()).thenReturn(proxyOpenIdConfiguration);

        OpenIdClientConfiguration openId = mock(OpenIdClientConfiguration.class);
        when(openId.getIssuer()).thenReturn(Optional.of(new URL("https://issuer.example.com")));
        when(cfg.getOpenid()).thenReturn(Optional.of(openId));

        ProxyHttpClient proxyHttpClient = mock(ProxyHttpClient.class);
        return new WellKnownProxyFilter(List.of(cfg), proxyHttpClient);
    }
}

