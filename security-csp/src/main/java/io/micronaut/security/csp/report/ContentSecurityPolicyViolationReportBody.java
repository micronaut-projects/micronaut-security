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
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PositiveOrZero;
import org.jspecify.annotations.Nullable;

/**
 * Body of a {@value ContentSecurityPolicyReport#TYPE_CSP_VIOLATION} report.
 *
 * <p>The values originate in a user agent and must be treated as untrusted input. In particular,
 * {@link #sample()} can contain attacker-controlled script or style content.</p>
 *
 * @param documentUrl URL of the document in which the violation occurred
 * @param referrer referrer of the document, or {@code null}
 * @param blockedUrl blocked resource URL or CSP resource description, or {@code null}
 * @param effectiveDirective directive whose enforcement caused the violation
 * @param originalPolicy complete policy that was enforced
 * @param sourceFile source file in which the violation occurred, or {@code null}
 * @param sample optional sample of the resource that caused the violation
 * @param disposition whether the policy was enforced or report-only
 * @param statusCode HTTP status code of the protected resource
 * @param lineNumber source line number, or {@code null}
 * @param columnNumber source column number, or {@code null}
 * @see <a href="https://w3c.github.io/webappsec-csp/#dictdef-cspviolationreportbody">CSPViolationReportBody</a>
 * @since 5.4.0
 */
@Serdeable
public record ContentSecurityPolicyViolationReportBody(
    @NotBlank @JsonProperty("documentURL") String documentUrl,
    @Nullable String referrer,
    @Nullable @JsonProperty("blockedURL") String blockedUrl,
    @NotBlank String effectiveDirective,
    @NotBlank String originalPolicy,
    @Nullable String sourceFile,
    @Nullable String sample,
    @NotNull ContentSecurityPolicyReportDisposition disposition,
    @NotNull @PositiveOrZero @Max(65_535) Integer statusCode,
    @Nullable @PositiveOrZero @Max(4_294_967_295L) Long lineNumber,
    @Nullable @PositiveOrZero @Max(4_294_967_295L) Long columnNumber
) implements ContentSecurityPolicyReportBody {
}
