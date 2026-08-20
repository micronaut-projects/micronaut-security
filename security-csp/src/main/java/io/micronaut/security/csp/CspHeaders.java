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
package io.micronaut.security.csp;

import io.micronaut.core.annotation.Internal;

/**
 * HTTP header names used to send enforcing and report-only Content Security Policies.
 *
 * <p>This class is internal because applications should normally let
 * {@link ContentSecurityPolicyFilter} select and write the appropriate header.</p>
 */
@Internal
public final class CspHeaders {
    /**
     * Header that causes user agents to enforce the supplied policy.
     */
    public static final String CONTENT_SECURITY_POLICY = "Content-Security-Policy";
    /**
     * Header that reports policy violations without enforcing the supplied policy.
     */
    public static final String CONTENT_SECURITY_POLICY_REPORT_ONLY = "Content-Security-Policy-Report-Only";

    private CspHeaders() {
    }
}
