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
import io.micronaut.security.csp.conf.baseuri.BaseUriConfigurationProperties;
import io.micronaut.security.csp.conf.connectsrc.ConnectSrcConfiguration;
import io.micronaut.security.csp.conf.connectsrc.ConnectSrcConfigurationProperties;
import io.micronaut.security.csp.conf.fontsrc.FontSrcConfigurationProperties;
import io.micronaut.security.csp.conf.formaction.FormActionConfigurationProperties;
import io.micronaut.security.csp.conf.frameancestors.FrameAncestorsConfigurationProperties;
import io.micronaut.security.csp.conf.imgsrc.ImgSrcConfigurationProperties;
import io.micronaut.security.csp.conf.reportto.ReportToConfigurationProperties;
import io.micronaut.security.csp.conf.reporturi.ReportUriConfigurationProperties;
import io.micronaut.security.csp.conf.requiretrustedtypesfor.RequireTrustedTypesForConfigurationProperties;
import io.micronaut.security.csp.conf.scriptsrc.ScriptSrcConfigurationProperties;
import io.micronaut.security.csp.nonce.ContentSecurityPolicyNonceGenerator;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultContentSecurityPolicyGeneratorTest {

    @Test
    void generatesSecureDefaultPolicy() {
        ContentSecurityPolicyConfiguration cfg = new ContentSecurityPolicyConfigurationProperties();
        ContentSecurityPolicyGenerator generator = defaultGenerator(cfg);

        assertEquals(List.of(
                new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.BASE_URI, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.DEFAULT_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.CONNECT_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.FONT_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.OBJECT_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.REQUIRE_TRUSTED_TYPES_FOR, "'script'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.FRAME_ANCESTORS, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.FRAME_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.IMG_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.MANIFEST_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.MEDIA_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.FORM_ACTION, "'self'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.WORKER_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.STYLE_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.SCRIPT_SRC, "'none'")
        ), policy(generator).directives());
    }

    @Test
    void omitsReportUriWhenEnabledWithoutUris() {
        ReportUriConfigurationProperties reportUri = new ReportUriConfigurationProperties();
        reportUri.setEnabled(true);
        ContentSecurityPolicy policy = policy(generator(ContentSecurityPolicyDirectiveConfigurations.builder().reportUri(reportUri)));

        assertNull(policy.reportUri());
    }

    @Test
    void omitsBlankReportUris() {
        ReportUriConfigurationProperties reportUri = new ReportUriConfigurationProperties();
        reportUri.setEnabled(true);
        reportUri.setValues(List.of("", "https://example.com/csp"));
        ContentSecurityPolicy policy = policy(generator(ContentSecurityPolicyDirectiveConfigurations.builder().reportUri(reportUri)));

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.REPORT_URI, "https://example.com/csp"),
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
                new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.CONNECT_SRC, "'self' https://api.example.com")));
    }

    @Test
    void invokesOverriddenDirectiveMethod() {
        ContentSecurityPolicyConfiguration configuration = new ContentSecurityPolicyConfigurationProperties();
        ContentSecurityPolicyGenerator generator = new DefaultContentSecurityPolicyGenerator(configuration, ContentSecurityPolicyDirectiveConfigurations.builder().build()) {
            @Override
            protected ContentSecurityPolicyDirective connectSrc() {
                return new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.CONNECT_SRC, "https://api.example.com");
            }
        };

        assertTrue(policy(generator).directives().contains(
                new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.CONNECT_SRC, "https://api.example.com")));
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

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.SCRIPT_SRC, "'nonce-nonce'"),
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

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.SCRIPT_SRC, "'nonce-nonce' 'strict-dynamic'"),
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

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.SCRIPT_SRC, "'unsafe-eval'"),
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

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.SCRIPT_SRC, "http: https:"),
                directives.get(directives.size() - 1));
    }

    @Test
    void fallsBackToNoneWhenNonceIsEnabledButTheRequestHasNoNonce() {
        ScriptSrcConfigurationProperties scriptSrcConfiguration = new ScriptSrcConfigurationProperties();
        scriptSrcConfiguration.setNonce(true);
        ContentSecurityPolicyGenerator generator = generator(new ContentSecurityPolicyConfigurationProperties(),
            currentRequest -> null, scriptSrcConfiguration, new ConnectSrcConfigurationProperties());

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.SCRIPT_SRC, "'none'"),
                policy(generator).scriptSrc());
    }

    @Test
    void doesNotFallBackToUnsafeInlineWhenTheNonceIsMissingOrInvalid() {
        ScriptSrcConfigurationProperties scriptSrcConfiguration = new ScriptSrcConfigurationProperties();
        scriptSrcConfiguration.setNonce(true);
        scriptSrcConfiguration.setUnsafeInline(true);
        scriptSrcConfiguration.setSelf(true);
        scriptSrcConfiguration.setValues(List.of("'UNSAFE-INLINE'"));

        for (String nonce : new String[] {null, "", "not a nonce"}) {
            ContentSecurityPolicyGenerator generator = generator(new ContentSecurityPolicyConfigurationProperties(),
                currentRequest -> nonce, scriptSrcConfiguration, new ConnectSrcConfigurationProperties());
            assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.SCRIPT_SRC, "'self'"),
                policy(generator).scriptSrc(), () -> "nonce " + nonce);
        }
        ContentSecurityPolicyGenerator withNonce = generator(new ContentSecurityPolicyConfigurationProperties(),
            currentRequest -> "abc", scriptSrcConfiguration, new ConnectSrcConfigurationProperties());
        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.SCRIPT_SRC, "'nonce-abc' 'self' 'unsafe-inline' 'UNSAFE-INLINE'"),
            policy(withNonce).scriptSrc(), "next to a nonce, 'unsafe-inline' is kept for browsers without nonce support");
    }

    @Test
    void writesNoneInsteadOfOmittingANonceDirectiveWithoutOtherSources() {
        ScriptSrcConfigurationProperties scriptSrcConfiguration = new ScriptSrcConfigurationProperties();
        scriptSrcConfiguration.setNonce(true);
        scriptSrcConfiguration.setUnsafeInline(true);
        scriptSrcConfiguration.setNone(false);
        ContentSecurityPolicyGenerator generator = generator(new ContentSecurityPolicyConfigurationProperties(),
            currentRequest -> null, scriptSrcConfiguration, new ConnectSrcConfigurationProperties());

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.SCRIPT_SRC, "'none'"), policy(generator).scriptSrc(),
            "an omitted script-src would fall back to default-src");
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

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.CONNECT_SRC,
                "'report-sha256' 'report-sha384' 'report-sha512'"),
                policy(generator).connectSrc());
    }

    @Test
    void omitsANonceOutsideTheBase64ValueGrammar() {
        ScriptSrcConfigurationProperties scriptSrcConfiguration = new ScriptSrcConfigurationProperties();
        scriptSrcConfiguration.setNonce(true);
        ContentSecurityPolicyGenerator generator = generator(new ContentSecurityPolicyConfigurationProperties(),
            currentRequest -> "abc'; script-src *", scriptSrcConfiguration, new ConnectSrcConfigurationProperties());

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.SCRIPT_SRC, "'none'"),
                policy(generator).scriptSrc());
    }

    @Test
    void acceptsABase64Nonce() {
        ScriptSrcConfigurationProperties scriptSrcConfiguration = new ScriptSrcConfigurationProperties();
        scriptSrcConfiguration.setNonce(true);
        ContentSecurityPolicyGenerator generator = generator(new ContentSecurityPolicyConfigurationProperties(),
            currentRequest -> "rAnd0m+/_-Value==", scriptSrcConfiguration, new ConnectSrcConfigurationProperties());

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.SCRIPT_SRC, "'nonce-rAnd0m+/_-Value=='"),
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
            new ContentSecurityPolicyConfigurationProperties(),
            ContentSecurityPolicyDirectiveConfigurations.builder().reportTo(reportTo).build()));

        assertTrue(exception.getMessage().startsWith("micronaut.security.csp.report-to.group must match"));
    }

    @Test
    void readsTheNonceFromTheRequestAttributeAndExposesItsConfiguration() {
        ContentSecurityPolicyConfiguration configuration = new ContentSecurityPolicyConfigurationProperties();
        ScriptSrcConfigurationProperties scriptSrcConfiguration = new ScriptSrcConfigurationProperties();
        scriptSrcConfiguration.setNonce(true);
        ContentSecurityPolicyDirectiveConfigurations directiveConfigurations = ContentSecurityPolicyDirectiveConfigurations.builder()
            .scriptSrc(scriptSrcConfiguration)
            .build();
        DefaultContentSecurityPolicyGenerator generator = new DefaultContentSecurityPolicyGenerator(configuration, directiveConfigurations);
        HttpRequest<?> request = HttpRequest.GET("/");
        request.setAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE, "abc123");

        assertEquals("abc123", generator.nonce(request));
        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.SCRIPT_SRC, "'nonce-abc123'"), policy(generator, request).scriptSrc());
        assertSame(configuration, generator.getCspConfiguration());
        assertSame(directiveConfigurations, generator.getDirectiveConfigurations());
    }

    @Test
    void ignoresWhitespaceOnlyValuesAndTrimsConfiguredValues() {
        ConnectSrcConfigurationProperties whitespaceOnly = new ConnectSrcConfigurationProperties();
        whitespaceOnly.setValues(List.of("   ", ""));
        ConnectSrcConfigurationProperties padded = new ConnectSrcConfigurationProperties();
        padded.setValues(List.of("  https://api.example.com  "));
        ContentSecurityPolicyConfiguration configuration = new ContentSecurityPolicyConfigurationProperties();

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.CONNECT_SRC, "'none'"),
            policy(generator(configuration, request -> null, new ScriptSrcConfigurationProperties(), whitespaceOnly)).connectSrc(),
            "a whitespace-only value must not suppress 'none'");
        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.CONNECT_SRC, "https://api.example.com"),
            policy(generator(configuration, request -> null, new ScriptSrcConfigurationProperties(), padded)).connectSrc());
    }

    @Test
    void rejectsABlankRequireTrustedTypesForValue() {
        RequireTrustedTypesForConfigurationProperties requireTrustedTypesFor = new RequireTrustedTypesForConfigurationProperties();
        requireTrustedTypesFor.setValue("  ");
        ContentSecurityPolicyDirectiveConfigurations.Builder builder = ContentSecurityPolicyDirectiveConfigurations.builder()
            .requireTrustedTypesFor(requireTrustedTypesFor);

        ConfigurationException exception = assertThrows(ConfigurationException.class, () -> generator(builder));

        assertEquals("micronaut.security.csp.require-trusted-types-for.value must not be blank while "
            + "micronaut.security.csp.require-trusted-types-for.enabled is true", exception.getMessage());
    }

    @Test
    void acceptsABlankRequireTrustedTypesForValueWhenTheDirectiveIsDisabled() {
        RequireTrustedTypesForConfigurationProperties requireTrustedTypesFor = new RequireTrustedTypesForConfigurationProperties();
        requireTrustedTypesFor.setEnabled(false);
        requireTrustedTypesFor.setValue("");

        assertNull(policy(generator(ContentSecurityPolicyDirectiveConfigurations.builder().requireTrustedTypesFor(requireTrustedTypesFor)))
            .requireTrustedTypesFor());
    }

    @Test
    void doesNotQuoteAnAlreadyQuotedExpressionTwice() {
        assertEquals("'self'", ContentSecurityPolicyUtils.wrapInSingleQuotes("'self'"));
        assertEquals("'self'", ContentSecurityPolicyUtils.wrapInSingleQuotes("self"));
    }

    @Test
    void addsReportUriWhenEnabled() {
        ReportUriConfigurationProperties reportUri = new ReportUriConfigurationProperties();
        reportUri.setEnabled(true);
        reportUri.setValues(List.of("https://example.com/csp-reports"));
        ContentSecurityPolicyGenerator generator = generator(ContentSecurityPolicyDirectiveConfigurations.builder().reportUri(reportUri));

        assertTrue(policy(generator).directives().contains(
                new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.REPORT_URI, "https://example.com/csp-reports")));
    }

    @Test
    void writesNoneForADirectiveWithoutFallbackThatHasNoSource() {
        FrameAncestorsConfigurationProperties frameAncestors = new FrameAncestorsConfigurationProperties();
        frameAncestors.setNone(false);
        BaseUriConfigurationProperties baseUri = new BaseUriConfigurationProperties();
        baseUri.setNone(false);
        FormActionConfigurationProperties formAction = new FormActionConfigurationProperties();
        formAction.setSelf(false);
        formAction.setNone(false);

        ContentSecurityPolicy policy = policy(generator(ContentSecurityPolicyDirectiveConfigurations.builder()
            .frameAncestors(frameAncestors).baseUri(baseUri).formAction(formAction)));

        assertEquals("frame-ancestors 'none'", policy.frameAncestors().toHeaderValue(), "an omitted frame-ancestors lets any origin frame the page");
        assertEquals("base-uri 'none'", policy.baseUri().toHeaderValue(), "an omitted base-uri allows an injected <base>");
        assertEquals("form-action 'none'", policy.formAction().toHeaderValue(), "an omitted form-action allows any form target");
    }

    @Test
    void disablingADirectiveWithoutFallbackOmitsIt() {
        FrameAncestorsConfigurationProperties frameAncestors = new FrameAncestorsConfigurationProperties();
        frameAncestors.setEnabled(false);

        assertNull(policy(generator(ContentSecurityPolicyDirectiveConfigurations.builder().frameAncestors(frameAncestors))).frameAncestors());
    }

    @Test
    void removesUnsafeInlineFromAMultiTokenValueWhenTheNonceIsMissing() {
        ScriptSrcConfigurationProperties scriptSrcConfiguration = new ScriptSrcConfigurationProperties();
        scriptSrcConfiguration.setNonce(true);
        scriptSrcConfiguration.setValues(List.of("'self' 'unsafe-inline'", "https://cdn.example.com\t'UNSAFE-INLINE'"));

        ContentSecurityPolicyGenerator withoutNonce = generator(new ContentSecurityPolicyConfigurationProperties(),
            currentRequest -> null, scriptSrcConfiguration, new ConnectSrcConfigurationProperties());
        ContentSecurityPolicyGenerator withNonce = generator(new ContentSecurityPolicyConfigurationProperties(),
            currentRequest -> "abc", scriptSrcConfiguration, new ConnectSrcConfigurationProperties());

        assertEquals("script-src 'self' https://cdn.example.com", policy(withoutNonce).scriptSrc().toHeaderValue());
        assertEquals("script-src 'nonce-abc' 'self' 'unsafe-inline' https://cdn.example.com 'UNSAFE-INLINE'", policy(withNonce).scriptSrc().toHeaderValue());
    }

    @Test
    void rejectsANonAsciiSourceExpressionThatBrowsersWouldIgnoreTheDirectiveFor() {
        for (String value : List.of("https://b\u00fccher.example", "'self'\u00a0")) {
            FrameAncestorsConfigurationProperties frameAncestors = new FrameAncestorsConfigurationProperties();
            frameAncestors.setValues(List.of(value));

            ConfigurationException exception = assertThrows(ConfigurationException.class,
                () -> generator(ContentSecurityPolicyDirectiveConfigurations.builder().frameAncestors(frameAncestors)));

            assertTrue(exception.getMessage().startsWith("micronaut.security.csp.frame-ancestors.values contains"), exception::getMessage);
            assertTrue(exception.getMessage().contains("non-ASCII"), exception::getMessage);
        }
    }

    @Test
    void acceptsTheAsciiFormOfAnInternationalizedHost() {
        FrameAncestorsConfigurationProperties frameAncestors = new FrameAncestorsConfigurationProperties();
        frameAncestors.setValues(List.of("https://xn--bcher-kva.example"));

        assertEquals("frame-ancestors https://xn--bcher-kva.example",
            policy(generator(ContentSecurityPolicyDirectiveConfigurations.builder().frameAncestors(frameAncestors))).frameAncestors().toHeaderValue());
    }

    @Test
    void omitsAWhitespaceOnlyReportUri() {
        ReportUriConfigurationProperties reportUri = new ReportUriConfigurationProperties();
        reportUri.setEnabled(true);
        reportUri.setValues(List.of("   "));

        assertNull(policy(generator(ContentSecurityPolicyDirectiveConfigurations.builder().reportUri(reportUri))).reportUri());
    }

    @Test
    void aRefreshDuringAPolicyGenerationDoesNotMixTheTwoConfigurations() {
        ImgSrcConfigurationProperties imgSrc = new ImgSrcConfigurationProperties();
        imgSrc.setValues(List.of("https://old.example.com"));
        FontSrcConfigurationProperties fontSrc = new FontSrcConfigurationProperties();
        fontSrc.setValues(List.of("https://old.example.com"));
        DefaultContentSecurityPolicyGenerator generator = new DefaultContentSecurityPolicyGenerator(new ContentSecurityPolicyConfigurationProperties(),
            ContentSecurityPolicyDirectiveConfigurations.builder().imgSrc(imgSrc).fontSrc(fontSrc).build()) {
            @Override
            protected @Nullable ContentSecurityPolicyDirective fontSrc() {
                ContentSecurityPolicyDirective directive = super.fontSrc();
                // A refresh lands between the font-src and img-src directives of this policy.
                imgSrc.setValues(List.of("https://new.example.com"));
                fontSrc.setValues(List.of("https://new.example.com"));
                refresh();
                return directive;
            }
        };

        ContentSecurityPolicy first = policy(generator);
        assertEquals("font-src https://old.example.com", first.fontSrc().toHeaderValue());
        assertEquals("img-src https://old.example.com", first.imgSrc().toHeaderValue(), "one policy is built from one configuration");
        assertEquals("img-src https://new.example.com", policy(generator).imgSrc().toHeaderValue());
    }

    @Test
    void keepsTheReportOnlyModeWhenARefreshIsRejected() {
        ContentSecurityPolicyConfigurationProperties configuration = new ContentSecurityPolicyConfigurationProperties();
        ImgSrcConfigurationProperties imgSrc = new ImgSrcConfigurationProperties();
        DefaultContentSecurityPolicyGenerator generator = new DefaultContentSecurityPolicyGenerator(configuration,
            ContentSecurityPolicyDirectiveConfigurations.builder().imgSrc(imgSrc).build());

        configuration.setReportOnly(true);
        imgSrc.setValues(List.of("https://a.example.com; script-src *"));
        generator.refresh();
        assertFalse(generator.isReportOnly(), "the previous policy keeps being enforced");

        imgSrc.setValues(List.of("https://a.example.com"));
        generator.refresh();
        assertTrue(generator.isReportOnly());
    }

    private static ContentSecurityPolicyGenerator generator(ContentSecurityPolicyDirectiveConfigurations.Builder directiveConfigurations) {
        return new DefaultContentSecurityPolicyGenerator(new ContentSecurityPolicyConfigurationProperties(), directiveConfigurations.build());
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
                                                            Function<HttpRequest<?>, @Nullable String> nonceProvider,
                                                            ScriptSrcConfigurationProperties scriptSrcConfiguration,
                                                            ConnectSrcConfiguration connectSrcConfiguration) {
        return new DefaultContentSecurityPolicyGenerator(configuration,
            ContentSecurityPolicyDirectiveConfigurations.builder()
                .scriptSrc(scriptSrcConfiguration)
                .connectSrc(connectSrcConfiguration)
                .build()) {
            @Override
            protected @Nullable String nonce(HttpRequest<?> request) {
                return nonceProvider.apply(request);
            }
        };
    }
}
