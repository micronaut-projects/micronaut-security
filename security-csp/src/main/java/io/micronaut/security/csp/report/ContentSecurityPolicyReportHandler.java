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
package io.micronaut.security.csp.report;

import io.micronaut.http.HttpRequest;

import java.util.List;

/**
 * Processes a batch of reports received through the Reporting API endpoint.
 *
 * <p>Implementations must treat report fields as untrusted input. In particular, URLs and content
 * samples can contain sensitive data and should not be logged without appropriate filtering.</p>
 *
 * @since 5.4.0
 */
@FunctionalInterface
public interface ContentSecurityPolicyReportHandler {
    /**
     * Handles one user-agent delivery batch.
     *
     * @param reports immutable list of reports in the order in which they were delivered
     * @param request request that delivered the reports; same-origin user agents may attach credentials
     */
    void handle(List<ContentSecurityPolicyReport> reports, HttpRequest<?> request);
}
