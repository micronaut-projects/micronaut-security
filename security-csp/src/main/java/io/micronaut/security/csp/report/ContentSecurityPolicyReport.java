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

import com.fasterxml.jackson.annotation.JsonProperty;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PositiveOrZero;

/**
 * A report envelope delivered by a user agent using the Reporting API.
 *
 * <p>The report {@link #type()} determines the concrete type returned by {@link #body()}. Content
 * Security Policy currently defines the {@value #TYPE_CSP_VIOLATION} and
 * {@value #TYPE_CSP_HASH} report types. Report data is untrusted input and may contain sensitive
 * URLs or content samples.</p>
 *
 * @param age milliseconds elapsed between report generation and delivery
 * @param type report type, such as {@code csp-violation}
 * @param url URL of the document or worker that generated the report
 * @param userAgent user agent of the request that generated the report
 * @param body report-type-specific data
 * @see <a href="https://w3c.github.io/reporting/#serialize-reports">Reporting API report serialization</a>
 * @since 5.4.0
 */
@Serdeable
public record ContentSecurityPolicyReport(
    @NotNull @PositiveOrZero Long age,
    @NotBlank String type,
    @NotBlank String url,
    @NotNull @JsonProperty("user_agent") String userAgent,
    @NotNull @Valid ContentSecurityPolicyReportBody body
) {
    /** CSP violation report type. */
    public static final String TYPE_CSP_VIOLATION = "csp-violation";

    /** CSP hash report type. */
    public static final String TYPE_CSP_HASH = "csp-hash";
}
