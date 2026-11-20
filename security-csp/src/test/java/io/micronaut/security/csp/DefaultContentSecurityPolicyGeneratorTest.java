/*
 * Copyright 2017-2026 original authors
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
package io.micronaut.security.csp;

import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfiguration;
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties;
import io.micronaut.security.csp.conf.ContentSecurityPolicyDirectiveConfigurations;
import io.micronaut.security.csp.conf.connectsrc.ConnectSrcConfiguration;
import io.micronaut.security.csp.conf.connectsrc.ConnectSrcConfigurationProperties;
import io.micronaut.security.csp.conf.reportto.ReportToConfigurationProperties;
import io.micronaut.security.csp.conf.scriptsrc.ScriptSrcConfigurationProperties;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultContentSecurityPolicyGeneratorTest {

    @Test
    void generatesSecureDefaultPolicy() {
        ContentSecurityPolicyConfiguration cfg = new ContentSecurityPolicyConfigurationProperties();
        ContentSecurityPolicyGenerator generator = defaultGenerator(cfg);

        assertEquals(List.of(
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.BASE_URI, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.DEFAULT_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.CONNECT_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.FONT_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.OBJECT_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.REQUIRE_TRUSTED_TYPES_FOR, "'script'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.FRAME_ANCESTORS, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.FRAME_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.IMG_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.MANIFEST_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.MEDIA_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.FORM_ACTION, "'self'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.WORKER_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.STYLE_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.SCRIPT_SRC, "'none'")
        ), policy(generator).directives());
    }

    @Test
    void omitsReportUriWhenEnabledWithoutUris() {
        ContentSecurityPolicyConfigurationProperties configuration = new ContentSecurityPolicyConfigurationProperties();
        configuration.setReportUriEnabled(true);
        ContentSecurityPolicy policy = policy(defaultGenerator(configuration));

        assertNull(policy.reportUri());
    }

    @Test
    void omitsBlankReportUris() {
        ContentSecurityPolicyConfigurationProperties configuration = new ContentSecurityPolicyConfigurationProperties();
        configuration.setReportUriEnabled(true);
        configuration.setReportUri(List.of("", "https://example.com/csp"));
        ContentSecurityPolicy policy = policy(defaultGenerator(configuration));

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.REPORT_URI, "https://example.com/csp"),
                policy.reportUri());
    }

    @Test
    void joinsConfiguredSourceExpressions() {
        ContentSecurityPolicyConfigurationProperties configuration = new ContentSecurityPolicyConfigurationProperties();
        ConnectSrcConfigurationProperties connectSrcConfiguration = new ConnectSrcConfigurationProperties();
        connectSrcConfiguration.setValues(List.of("'self'", "https://api.example.com"));

        ContentSecurityPolicyGenerator generator = generator(configuration, request -> "unused",
            new ScriptSrcConfigurationProperties(), connectSrcConfiguration);

        assertTrue(policy(generator).directives().contains(
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.CONNECT_SRC, "'self' https://api.example.com")));
    }

    @Test
    void invokesOverriddenDirectiveMethod() {
        ContentSecurityPolicyConfiguration configuration = new ContentSecurityPolicyConfigurationProperties();
        ContentSecurityPolicyGenerator generator = new DefaultContentSecurityPolicyGenerator(configuration, ContentSecurityPolicyDirectiveConfigurations.builder().build()) {
            @Override
            protected ContentSecurityPolicyDirective connectSrc() {
                return new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.CONNECT_SRC, "https://api.example.com");
            }
        };

        assertTrue(policy(generator).directives().contains(
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.CONNECT_SRC, "https://api.example.com")));
    }

    @Test
    void addsRequestNonceToScriptSource() {
        HttpRequest<?> request = HttpRequest.GET("/");
        ContentSecurityPolicyConfiguration configuration = new ContentSecurityPolicyConfigurationProperties();
        ScriptSrcConfigurationProperties scriptSrcConfiguration = new ScriptSrcConfigurationProperties();
        scriptSrcConfiguration.setNonce(true);
        ContentSecurityPolicyGenerator generator = generator(configuration, req -> "nonce",
            scriptSrcConfiguration, new ConnectSrcConfigurationProperties());

        List<ContentSecurityPolicyDirective> directives = policy(generator, request).directives();

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.SCRIPT_SRC, "'nonce-nonce'"),
                directives.get(directives.size() - 1));
    }

    @Test
    void addsStrictDynamicToScriptSourceWhenEnabled() {
        ContentSecurityPolicyConfigurationProperties configuration = new ContentSecurityPolicyConfigurationProperties();
        ScriptSrcConfigurationProperties scriptSrcConfiguration = new ScriptSrcConfigurationProperties();
        scriptSrcConfiguration.setNonce(true);
        scriptSrcConfiguration.setStrictDynamic(true);
        HttpRequest<?> request = HttpRequest.GET("/");
        ContentSecurityPolicyGenerator generator = generator(configuration, currentRequest -> "nonce",
            scriptSrcConfiguration, new ConnectSrcConfigurationProperties());

        List<ContentSecurityPolicyDirective> directives = policy(generator, request).directives();

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.SCRIPT_SRC, "'nonce-nonce' 'strict-dynamic'"),
                directives.get(directives.size() - 1));
    }

    @Test
    void addsUnsafeEvalToScriptSourceWhenEnabled() {
        ContentSecurityPolicyConfigurationProperties configuration = new ContentSecurityPolicyConfigurationProperties();
        ScriptSrcConfigurationProperties scriptSrcConfiguration = new ScriptSrcConfigurationProperties();
        scriptSrcConfiguration.setUnsafeEval(true);
        HttpRequest<?> request = HttpRequest.GET("/");
        ContentSecurityPolicyGenerator generator = generator(configuration, currentRequest -> "nonce",
            scriptSrcConfiguration, new ConnectSrcConfigurationProperties());

        List<ContentSecurityPolicyDirective> directives = policy(generator, request).directives();

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.SCRIPT_SRC, "'unsafe-eval'"),
                directives.get(directives.size() - 1));
    }

    @Test
    void addsUnquotedHttpAndHttpsSchemeSourcesWhenEnabled() {
        ContentSecurityPolicyConfigurationProperties configuration = new ContentSecurityPolicyConfigurationProperties();
        ScriptSrcConfigurationProperties scriptSrcConfiguration = new ScriptSrcConfigurationProperties();
        scriptSrcConfiguration.setHttp(true);
        scriptSrcConfiguration.setHttps(true);
        HttpRequest<?> request = HttpRequest.GET("/");
        ContentSecurityPolicyGenerator generator = generator(configuration, currentRequest -> "nonce",
            scriptSrcConfiguration, new ConnectSrcConfigurationProperties());
        List<ContentSecurityPolicyDirective> directives = policy(generator, request).directives();

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.SCRIPT_SRC, "http: https:"),
                directives.get(directives.size() - 1));
    }

    @Test
    void fallsBackToNoneWhenNonceIsEnabledButTheRequestHasNoNonce() {
        ScriptSrcConfigurationProperties scriptSrcConfiguration = new ScriptSrcConfigurationProperties();
        scriptSrcConfiguration.setNonce(true);
        ContentSecurityPolicyGenerator generator = generator(new ContentSecurityPolicyConfigurationProperties(),
            currentRequest -> null, scriptSrcConfiguration, new ConnectSrcConfigurationProperties());

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.SCRIPT_SRC, "'none'"),
                policy(generator).scriptSrc());
    }

    @Test
    void emitsKeywordSourcesEnabledByACustomDirectiveConfiguration() {
        ConnectSrcConfiguration connectSrcConfiguration = new ConnectSrcConfiguration() {
            @Override
            public List<String> getValues() {
                return List.of();
            }

            @Override
            public boolean isEnabled() {
                return true;
            }

            @Override
            public boolean isReportSha256() {
                return true;
            }

            @Override
            public boolean isReportSha384() {
                return true;
            }

            @Override
            public boolean isReportSha512() {
                return true;
            }
        };
        ContentSecurityPolicyGenerator generator = generator(new ContentSecurityPolicyConfigurationProperties(),
            currentRequest -> null, new ScriptSrcConfigurationProperties(), connectSrcConfiguration);

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.CONNECT_SRC,
                "'report-sha256' 'report-sha384' 'report-sha512'"),
                policy(generator).connectSrc());
    }

    @Test
    void omitsANonceOutsideTheBase64ValueGrammar() {
        ScriptSrcConfigurationProperties scriptSrcConfiguration = new ScriptSrcConfigurationProperties();
        scriptSrcConfiguration.setNonce(true);
        ContentSecurityPolicyGenerator generator = generator(new ContentSecurityPolicyConfigurationProperties(),
            currentRequest -> "abc'; script-src *", scriptSrcConfiguration, new ConnectSrcConfigurationProperties());

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.SCRIPT_SRC, "'none'"),
                policy(generator).scriptSrc());
    }

    @Test
    void acceptsABase64Nonce() {
        ScriptSrcConfigurationProperties scriptSrcConfiguration = new ScriptSrcConfigurationProperties();
        scriptSrcConfiguration.setNonce(true);
        ContentSecurityPolicyGenerator generator = generator(new ContentSecurityPolicyConfigurationProperties(),
            currentRequest -> "rAnd0m+/_-Value==", scriptSrcConfiguration, new ConnectSrcConfigurationProperties());

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.SCRIPT_SRC, "'nonce-rAnd0m+/_-Value=='"),
                policy(generator).scriptSrc());
    }

    @Test
    void omitsDirectiveWithoutNoneAndWithoutSources() {
        ConnectSrcConfigurationProperties connectSrcConfiguration = new ConnectSrcConfigurationProperties();
        connectSrcConfiguration.setNone(false);
        ContentSecurityPolicyGenerator generator = generator(new ContentSecurityPolicyConfigurationProperties(),
            currentRequest -> null, new ScriptSrcConfigurationProperties(), connectSrcConfiguration);

        assertNull(policy(generator).connectSrc());
    }

    @Test
    void returnsNullPolicyWhenNoDirectiveIsGenerated() {
        ContentSecurityPolicyGenerator generator = new DefaultContentSecurityPolicyGenerator(new ContentSecurityPolicyConfigurationProperties(),
            ContentSecurityPolicyDirectiveConfigurations.builder().build()) {
            @Override
            protected List<ContentSecurityPolicyDirective> directives(HttpRequest<?> request) {
                return List.of();
            }
        };

        assertNull(generator.contentSecurityPolicy(HttpRequest.GET("/")));
    }

    @Test
    void rejectsAnInvalidReportingGroupWithoutBeanValidation() {
        ReportToConfigurationProperties reportTo = new ReportToConfigurationProperties();
        reportTo.setEnabled(true);
        reportTo.setGroup("CSP; script-src *");

        ConfigurationException exception = assertThrows(ConfigurationException.class, () -> new DefaultContentSecurityPolicyGenerator(
            new ContentSecurityPolicyConfigurationProperties(), currentRequest -> null,
            ContentSecurityPolicyDirectiveConfigurations.builder().reportTo(reportTo).build()));

        assertTrue(exception.getMessage().startsWith("micronaut.security.csp.report-to.group must match"));
    }

    @Test
    void doesNotQuoteAnAlreadyQuotedExpressionTwice() {
        assertEquals("'self'", ContentSecurityPolicyUtils.wrapInSingleQuotes("'self'"));
        assertEquals("'self'", ContentSecurityPolicyUtils.wrapInSingleQuotes("self"));
    }

    @Test
    void addsReportUriWhenEnabled() {
        ContentSecurityPolicyConfigurationProperties configuration = new ContentSecurityPolicyConfigurationProperties();
        configuration.setReportUriEnabled(true);
        configuration.setReportUri(List.of("https://example.com/csp-reports"));
        ContentSecurityPolicyGenerator generator = defaultGenerator(configuration);

        assertTrue(policy(generator).directives().contains(
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.REPORT_URI, "https://example.com/csp-reports")));
    }

    private static ContentSecurityPolicyGenerator defaultGenerator(ContentSecurityPolicyConfiguration configuration) {
        return new DefaultContentSecurityPolicyGenerator(configuration, ContentSecurityPolicyDirectiveConfigurations.builder().build());
    }

    private static ContentSecurityPolicy policy(ContentSecurityPolicyGenerator generator) {
        return policy(generator, HttpRequest.GET("/"));
    }

    private static ContentSecurityPolicy policy(ContentSecurityPolicyGenerator generator, HttpRequest<?> request) {
        ContentSecurityPolicy policy = generator.contentSecurityPolicy(request);
        assertNotNull(policy);
        return policy;
    }

    private static ContentSecurityPolicyGenerator generator(ContentSecurityPolicyConfiguration configuration,
                                                            Function<HttpRequest<?>, String> nonceProvider,
                                                            ScriptSrcConfigurationProperties scriptSrcConfiguration,
                                                            ConnectSrcConfiguration connectSrcConfiguration) {
        return new DefaultContentSecurityPolicyGenerator(configuration,
            nonceProvider,
            ContentSecurityPolicyDirectiveConfigurations.builder()
                .scriptSrc(scriptSrcConfiguration)
                .connectSrc(connectSrcConfiguration)
                .build());
    }
}
