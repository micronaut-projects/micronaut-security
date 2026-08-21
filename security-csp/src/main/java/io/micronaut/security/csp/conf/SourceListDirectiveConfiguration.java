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
package io.micronaut.security.csp.conf;

import java.util.Set;

/**
 * Configuration contract for CSP directives whose value is a source list.
 *
 * @since 5.4.0
 */
public interface SourceListDirectiveConfiguration extends DirectiveConfiguration {
    /**
     * Returns additional source expressions in their serialized CSP form.
     *
     * <p>Keyword and hash source expressions must include any quotes required by CSP. Host and
     * scheme source expressions are not quoted.</p>
     *
     * @return the additional source expressions, in response-header order
     */
    Set<String> getValues();
}
