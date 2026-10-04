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

/**
 * Disposition of the policy that generated a violation report.
 *
 * @since 5.4.0
 */
@Serdeable
public enum ContentSecurityPolicyReportDisposition {
    /** The policy blocked the violating operation. */
    @JsonProperty("enforce")
    ENFORCE,

    /** The policy reported the violation without blocking it. */
    @JsonProperty("report")
    REPORT
}
