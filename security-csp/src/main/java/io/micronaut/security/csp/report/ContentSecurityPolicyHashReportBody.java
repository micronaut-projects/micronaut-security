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
import jakarta.validation.constraints.NotBlank;

/**
 * Body of a {@value ContentSecurityPolicyReport#TYPE_CSP_HASH} report.
 *
 * @param documentUrl URL of the document that loaded the subresource
 * @param subresourceUrl URL of the subresource for which a hash was requested
 * @param hash cryptographic digest prefixed by its algorithm
 * @param destination request destination, such as {@code script}
 * @param type kind of resource that was hashed, currently {@code subresource}
 * @see <a href="https://w3c.github.io/webappsec-csp/#csp-hash-report">CSP hash reports</a>
 * @since 5.4.0
 */
@Serdeable
public record ContentSecurityPolicyHashReportBody(
    @NotBlank @JsonProperty("document_url") String documentUrl,
    @NotBlank @JsonProperty("subresource_url") String subresourceUrl,
    @NotBlank String hash,
    @NotBlank String destination,
    @NotBlank String type
) implements ContentSecurityPolicyReportBody {
}
