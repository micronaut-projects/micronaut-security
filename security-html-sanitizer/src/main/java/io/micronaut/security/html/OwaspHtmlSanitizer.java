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
package io.micronaut.security.html;

import io.micronaut.http.util.HtmlSanitizer;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;
import org.owasp.html.PolicyFactory;

/**
 * OWASP-backed implementation of {@link HtmlSanitizer}.
 *
 * @author Sergio del Amo
 * @since 5.1.0
 */
@Singleton
public class OwaspHtmlSanitizer implements HtmlSanitizer {
    private final PolicyFactory policyFactory;

    /**
     * Constructs an OWASP-backed HTML sanitizer.
     *
     * @param policyFactory The OWASP policy factory
     */
    public OwaspHtmlSanitizer(PolicyFactory policyFactory) {
        this.policyFactory = policyFactory;
    }

    @Override
    public String sanitize(@Nullable String html) {
        if (html == null) {
            return "";
        }
        return policyFactory.sanitize(html);
    }
}
