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

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.validation.constraints.NotBlank;
import org.jspecify.annotations.Nullable;

/**
 * Body of a {@value ContentSecurityPolicyReport#TYPE_CSP_HASH} report.
 *
 * <p>Fields use the camelCase names that Chromium sends ({@code subresourceURL}). The snake_case
 * names used in the specification's example ({@code subresource_url}, {@code document_url}) are
 * also accepted. Chromium does not include the document URL in the body; use
 * {@link ContentSecurityPolicyReport#url()} instead. Only {@link #hash()} is required.</p>
 *
 * @param documentUrl URL of the document that loaded the subresource, or {@code null} when the user agent omits it
 * @param subresourceUrl URL of the subresource for which a hash was requested, or {@code null}
 * @param hash cryptographic digest prefixed by its algorithm
 * @param destination request destination, such as {@code script}, or {@code null}
 * @param type kind of resource that was hashed, currently {@code subresource}, or {@code null}
 * @see <a href="https://w3c.github.io/webappsec-csp/#csp-hash-report">CSP hash reports</a>
 * @since 5.4.0
 */
@Serdeable
public record ContentSecurityPolicyHashReportBody(
    @Nullable @JsonProperty("documentURL") @JsonAlias("document_url") String documentUrl,
    @Nullable @JsonProperty("subresourceURL") @JsonAlias("subresource_url") String subresourceUrl,
    @NotBlank String hash,
    @Nullable String destination,
    @Nullable String type
) implements ContentSecurityPolicyReportBody {
}
