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
package io.micronaut.security.csp.filters;

import io.micronaut.context.ApplicationContext;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.filter.ServerFilterPhase;
import io.micronaut.security.csp.ContentSecurityPolicyGenerator;
import io.micronaut.security.csp.DefaultContentSecurityPolicyGenerator;
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties;
import io.micronaut.security.csp.conf.ContentSecurityPolicyDirectiveConfigurations;
import io.micronaut.security.csp.conf.scriptsrc.ScriptSrcConfigurationProperties;
import io.micronaut.security.csp.conf.stylesrc.StyleSrcConfigurationProperties;
import io.micronaut.security.csp.nonce.ContentSecurityPolicyNonceGenerator;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ContentSecurityPolicyFilterTest {
    private static final ContentSecurityPolicyGenerator CUSTOM_GENERATOR = request -> null;

    @Test
    void marksTheRequestAndGeneratesOneNonceSharedByTheDirectives() {
        CountingNonceGenerator nonceGenerator = new CountingNonceGenerator();
        ScriptSrcConfigurationProperties scriptSrc = new ScriptSrcConfigurationProperties();
        scriptSrc.setNonce(true);
        StyleSrcConfigurationProperties styleSrc = new StyleSrcConfigurationProperties();
        styleSrc.setNonce(true);
        MutableHttpRequest<?> request = HttpRequest.GET("/");

        new ContentSecurityPolicyFilter(nonceGenerator, CUSTOM_GENERATOR, List.of(scriptSrc, styleSrc)).filterRequest(request);

        assertTrue(request.getAttribute(ContentSecurityPolicyFilter.MATCHED_ATTRIBUTE).isPresent());
        assertEquals("nonce1", request.getAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE, String.class).orElseThrow());
        assertEquals(1, nonceGenerator.calls.get(), "directives share one nonce per request");
    }

    @Test
    void marksTheRequestWithoutANonceWhenNoDirectiveUsesNonces() {
        CountingNonceGenerator nonceGenerator = new CountingNonceGenerator();
        MutableHttpRequest<?> request = HttpRequest.GET("/");

        new ContentSecurityPolicyFilter(nonceGenerator, CUSTOM_GENERATOR, List.of(new ScriptSrcConfigurationProperties())).filterRequest(request);

        assertTrue(request.getAttribute(ContentSecurityPolicyFilter.MATCHED_ATTRIBUTE).isPresent());
        assertFalse(request.getAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE).isPresent());
        assertEquals(0, nonceGenerator.calls.get());
    }

    @Test
    void generatesNoNonceForADisabledDirective() {
        ScriptSrcConfigurationProperties scriptSrc = new ScriptSrcConfigurationProperties();
        scriptSrc.setNonce(true);
        scriptSrc.setEnabled(false);
        MutableHttpRequest<?> request = HttpRequest.GET("/");

        new ContentSecurityPolicyFilter(new CountingNonceGenerator(), CUSTOM_GENERATOR, List.of(scriptSrc)).filterRequest(request);

        assertFalse(request.getAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE).isPresent());
    }

    @Test
    void readsWhetherADirectiveUsesNoncesForEachRequest() {
        ScriptSrcConfigurationProperties scriptSrc = new ScriptSrcConfigurationProperties();
        ContentSecurityPolicyFilter filter = new ContentSecurityPolicyFilter(new CountingNonceGenerator(), CUSTOM_GENERATOR, List.of(scriptSrc));
        MutableHttpRequest<?> before = HttpRequest.GET("/");
        filter.filterRequest(before);

        scriptSrc.setNonce(true);
        MutableHttpRequest<?> after = HttpRequest.GET("/");
        filter.filterRequest(after);

        assertFalse(before.getAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE).isPresent());
        assertTrue(after.getAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE).isPresent(),
            "a configuration refresh that enables nonces must take effect without a restart");
    }

    @Test
    void followsThePolicyOfTheDefaultGeneratorRatherThanTheRebound() {
        ScriptSrcConfigurationProperties scriptSrc = new ScriptSrcConfigurationProperties();
        scriptSrc.setNonce(true);
        DefaultContentSecurityPolicyGenerator generator = new DefaultContentSecurityPolicyGenerator(new ContentSecurityPolicyConfigurationProperties(),
            ContentSecurityPolicyDirectiveConfigurations.builder().scriptSrc(scriptSrc).build()) { };
        ContentSecurityPolicyFilter filter = new ContentSecurityPolicyFilter(new CountingNonceGenerator(), generator, List.of(scriptSrc));

        // Re-bound by a refresh that the generator has not accepted.
        scriptSrc.setNonce(false);
        MutableHttpRequest<?> request = HttpRequest.GET("/");
        filter.filterRequest(request);

        assertTrue(request.getAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE).isPresent(),
            "the policy still adds the nonce, so the request needs one");
    }

    @Test
    void runsBeforeTheOtherServerFilterPhases() {
        assertEquals(ServerFilterPhase.FIRST.before(),
            new ContentSecurityPolicyFilter(new CountingNonceGenerator(), CUSTOM_GENERATOR, List.of()).getOrder());
    }

    @Test
    void filterIsLoadedWhetherOrNotADirectiveUsesNonces() {
        try (ApplicationContext context = ApplicationContext.run()) {
            assertTrue(context.containsBean(ContentSecurityPolicyFilter.class));
        }
    }

    @Test
    void filterIsNotLoadedWhenTheModuleIsDisabled() {
        try (ApplicationContext context = ApplicationContext.run(Map.of(
            "micronaut.security.csp.enabled", false,
            "micronaut.security.csp.script-src.nonce", true))) {
            assertFalse(context.containsBean(ContentSecurityPolicyFilter.class));
        }
    }

    @Test
    void filterIsNotLoadedWhenTheFilterIsDisabled() {
        try (ApplicationContext context = ApplicationContext.run(Map.of(
            "micronaut.security.csp.filter.enabled", false,
            "micronaut.security.csp.script-src.nonce", true))) {
            assertFalse(context.containsBean(ContentSecurityPolicyFilter.class));
        }
    }

    private static final class CountingNonceGenerator implements ContentSecurityPolicyNonceGenerator {
        private final AtomicInteger calls = new AtomicInteger();

        @Override
        public String generateNonce(HttpRequest<?> request) {
            return "nonce" + calls.incrementAndGet();
        }
    }
}
