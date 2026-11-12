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
package io.micronaut.security.csp.conf.reportTo;

import io.micronaut.core.util.Toggleable;

/**
 * Configuration for the {@code report-to} directive.
 *
 * <p>The directive value identifies an endpoint group declared by the {@code Reporting-Endpoints}
 * response header. It is a single group name, not a URL or CSP source list.</p>
 *
 * @since 5.4.0
 */
public interface ReportToConfiguration extends Toggleable {
    /**
     * Returns the named Reporting API endpoint selected by the directive.
     *
     * @return the Reporting API endpoint group referenced by {@code report-to}
     */
    String getGroup();
}
