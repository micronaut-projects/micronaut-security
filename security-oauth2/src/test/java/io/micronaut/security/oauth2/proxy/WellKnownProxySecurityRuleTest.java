package io.micronaut.security.oauth2.proxy;

import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.rules.SecurityRuleResult;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class WellKnownProxySecurityRuleTest {

    @Test
    void proxiedPathIsAllowedAnonymously() throws MalformedURLException {
        WellKnownProxySecurityRule rule = newRule(false, true);
        assertEquals(SecurityRuleResult.ALLOWED, check(rule, HttpMethod.GET, WellKnownProxyFilter.OPENID_CONFIGURATION_PATH));

        rule = newRule(true, false);
        assertEquals(SecurityRuleResult.ALLOWED, check(rule, HttpMethod.GET, WellKnownProxyFilter.OAUTH_AUTHORIZATION_SERVER_WELL_KNOWN_PATH));
    }

    @Test
    void wellKnownPathWhichIsNotProxiedIsNotAllowedByTheRule() throws MalformedURLException {
        WellKnownProxySecurityRule rule = newRule(false, true);
        assertEquals(SecurityRuleResult.UNKNOWN, check(rule, HttpMethod.GET, WellKnownProxyFilter.OAUTH_AUTHORIZATION_SERVER_WELL_KNOWN_PATH));

        rule = newRule(true, false);
        assertEquals(SecurityRuleResult.UNKNOWN, check(rule, HttpMethod.GET, WellKnownProxyFilter.OPENID_CONFIGURATION_PATH));
    }

    @Test
    void nonGetRequestsAndOtherPathsAreNotAllowedByTheRule() throws MalformedURLException {
        WellKnownProxySecurityRule rule = newRule(true, true);
        assertEquals(SecurityRuleResult.UNKNOWN, check(rule, HttpMethod.POST, WellKnownProxyFilter.OPENID_CONFIGURATION_PATH));
        assertEquals(SecurityRuleResult.UNKNOWN, check(rule, HttpMethod.GET, "/.well-known/jwks.json"));
        assertEquals(SecurityRuleResult.UNKNOWN, Mono.from(rule.check(null, null)).block());
    }

    @Test
    void disabledClientDoesNotAllowAnonymousAccess() throws MalformedURLException {
        WellKnownProxySecurityRule rule = new WellKnownProxySecurityRule(List.of(newClientConfiguration(false, true, true)));
        assertEquals(SecurityRuleResult.UNKNOWN, check(rule, HttpMethod.GET, WellKnownProxyFilter.OPENID_CONFIGURATION_PATH));
        assertEquals(SecurityRuleResult.UNKNOWN, check(rule, HttpMethod.GET, WellKnownProxyFilter.OAUTH_AUTHORIZATION_SERVER_WELL_KNOWN_PATH));
    }

    @Test
    void withoutProxySettingsNothingIsAllowed() {
        WellKnownProxySecurityRule rule = new WellKnownProxySecurityRule(Collections.emptyList());
        assertEquals(SecurityRuleResult.UNKNOWN, check(rule, HttpMethod.GET, WellKnownProxyFilter.OPENID_CONFIGURATION_PATH));
    }

    private static SecurityRuleResult check(WellKnownProxySecurityRule rule, HttpMethod method, String path) {
        HttpRequest<?> request = mock(HttpRequest.class);
        when(request.getMethod()).thenReturn(method);
        when(request.getPath()).thenReturn(path);
        return Mono.from(rule.check(request, null)).block();
    }

    private static WellKnownProxySecurityRule newRule(boolean proxyOauthAuthorizationServer, boolean proxyOpenIdConfiguration) throws MalformedURLException {
        return new WellKnownProxySecurityRule(List.of(newClientConfiguration(true, proxyOauthAuthorizationServer, proxyOpenIdConfiguration)));
    }

    private static OauthClientConfiguration newClientConfiguration(boolean enabled, boolean proxyOauthAuthorizationServer, boolean proxyOpenIdConfiguration) throws MalformedURLException {
        OauthClientConfiguration cfg = mock(OauthClientConfiguration.class);
        when(cfg.isEnabled()).thenReturn(enabled);
        when(cfg.isProxyWellKnownOauthAuthorizationServer()).thenReturn(proxyOauthAuthorizationServer);
        when(cfg.isProxyWellKnownOpenidConfiguration()).thenReturn(proxyOpenIdConfiguration);
        OpenIdClientConfiguration openId = mock(OpenIdClientConfiguration.class);
        when(openId.getIssuer()).thenReturn(Optional.of(new URL("https://issuer.example.com")));
        when(cfg.getOpenid()).thenReturn(Optional.of(openId));
        return cfg;
    }
}
