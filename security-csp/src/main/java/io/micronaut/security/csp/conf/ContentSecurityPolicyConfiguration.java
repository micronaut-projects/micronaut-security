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

/**
 * Configuration for Content Security Policy response headers.
 *
 * <p>This root configuration controls policy-wide behavior, such as report-only mode. Source-list
 * directives are configured through their individual types in child packages, for example
 * {@code io.micronaut.security.csp.conf.imgsrc.ImgSrcConfiguration}; their values are serialized as
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
 * <p>The module is enabled and disabled with the {@code micronaut.security.csp.enabled} property,
 * which a condition reads directly; a replacement bean cannot disable the module.</p>
 *
 * @since 5.6.0
 */
public interface ContentSecurityPolicyConfiguration {
    /**
     * Determines whether the policy is observational rather than enforcing.
     *
     * @return whether to report policy violations without enforcing the policy
     */
    boolean isReportOnly();
}
