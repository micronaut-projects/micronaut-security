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

import io.micronaut.core.util.Toggleable;

import java.util.List;

/**
 * Configuration for Content Security Policy response headers.
 *
 * <p>This root configuration controls policy-wide behavior, such as report-only mode. Source-list
 * directives are configured through their individual types in child packages, for example
 * {@code io.micronaut.security.csp.conf.imgSrc.ImgSrcConfiguration}; their values are serialized as
 * CSP's space-separated source expression lists.</p>
 *
 * <p>URL-based CSP policies are ineffective as a primary defense against cross-site scripting because
 * an allowlisted origin can contain attacker-controlled or exploitable content. Prefer nonce- or
 * hash-based {@code script-src} policies, optionally combined with {@code 'strict-dynamic'}, over
 * URL source expressions. Configure script URLs only when required for compatibility.</p>
 *
 * <p>When enabled, a more-specific fetch directive takes precedence over {@code default-src}. An
 * application can disable a directive when it needs to manage that restriction in a different
 * response header or does not want the module to emit it.</p>
 *
 * @since 5.4.0
 */
public interface ContentSecurityPolicyConfiguration extends Toggleable {
    /**
     * Determines whether the policy is observational rather than enforcing.
     *
     * @return whether to report policy violations without enforcing the policy
     */
    boolean isReportOnly();

    /**
     * Determines whether the deprecated {@code report-uri} directive is generated.
     *
     * @return whether to send CSP violation reports to the configured legacy reporting endpoints
     * @since 5.4.0
     */
    boolean isReportUriEnabled();

    /**
     * Supplies the endpoints for the deprecated {@code report-uri} directive.
     *
     * @return the reporting endpoint URLs for the deprecated {@code report-uri} directive
     * @since 5.4.0
     */
    List<String> getReportUri();

    /**
     * Determines whether Trusted Types enforcement is generated.
     *
     * @return whether to require Trusted Types for selected DOM injection sinks
     */
    boolean isRequireTrustedTypesForEnabled();

    /**
     * Supplies the Trusted Types sink group to protect.
     *
     * @return the Trusted Types sink group, such as {@code 'script'}, to enforce
     */
    String getRequireTrustedTypesFor();
}
