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
package io.micronaut.security.csp.conf.reporturi;

import io.micronaut.core.util.Toggleable;

import java.util.List;

/**
 * Configuration for the deprecated {@code report-uri} directive.
 *
 * <p>The directive lists endpoint URLs that receive violation reports in the deprecated CSP
 * reporting format. Prefer the {@code report-to} directive and the Reporting API.</p>
 *
 * @since 5.6.0
 */
public interface ReportUriConfiguration extends Toggleable {
    /**
     * Returns the endpoint URLs written in the directive.
     *
     * @return the reporting endpoint URLs of the deprecated {@code report-uri} directive
     */
    List<String> getValues();
}
