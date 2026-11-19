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

import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.security.csp.conf.NonceConfiguration;
import io.micronaut.security.csp.conf.scriptsrc.ScriptSrcConfigurationProperties;
import io.micronaut.security.csp.conf.stylesrc.StyleSrcConfigurationProperties;
import io.micronaut.security.csp.nonce.ContentSecurityPolicyNonceGenerator;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ContentSecurityPolicyFilterTest {

    @Test
    void doesNotGenerateANonceWhenTheOnlyNonceDirectiveIsDisabled() {
        ScriptSrcConfigurationProperties scriptSrc = new ScriptSrcConfigurationProperties();
        scriptSrc.setNonce(true);
        scriptSrc.setEnabled(false);
        CountingNonceGenerator nonceGenerator = new CountingNonceGenerator();
        MutableHttpRequest<?> request = HttpRequest.GET("/");

        new ContentSecurityPolicyFilter(List.of(scriptSrc, new StyleSrcConfigurationProperties()), nonceGenerator).generateNonce(request);

        assertTrue(request.getAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE).isEmpty());
        assertEquals(0, nonceGenerator.calls.get());
    }

    @Test
    void generatesOneNonceWhenAnEnabledDirectiveUsesNonces() {
        ScriptSrcConfigurationProperties scriptSrc = new ScriptSrcConfigurationProperties();
        scriptSrc.setNonce(true);
        StyleSrcConfigurationProperties styleSrc = new StyleSrcConfigurationProperties();
        styleSrc.setNonce(true);
        CountingNonceGenerator nonceGenerator = new CountingNonceGenerator();
        MutableHttpRequest<?> request = HttpRequest.GET("/");

        new ContentSecurityPolicyFilter(List.of(scriptSrc, styleSrc), nonceGenerator).generateNonce(request);

        assertEquals("nonce1", request.getAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE, String.class).orElseThrow());
        assertEquals(1, nonceGenerator.calls.get(), "directives share one nonce per request");
    }

    @Test
    void treatsANonToggleableNonceConfigurationAsEnabled() {
        NonceConfiguration alwaysNonce = () -> true;
        CountingNonceGenerator nonceGenerator = new CountingNonceGenerator();
        MutableHttpRequest<?> request = HttpRequest.GET("/");

        new ContentSecurityPolicyFilter(List.of(alwaysNonce), nonceGenerator).generateNonce(request);

        assertEquals(1, nonceGenerator.calls.get());
    }

    private static final class CountingNonceGenerator implements ContentSecurityPolicyNonceGenerator {
        private final AtomicInteger calls = new AtomicInteger();

        @Override
        public String generateNonce(HttpRequest<?> request) {
            return "nonce" + calls.incrementAndGet();
        }
    }
}
