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
package io.micronaut.security.fetchmetadata;

import io.micronaut.core.order.Ordered;

/**
 * Evaluates a request using Fetch Metadata or related request information.
 *
 * <p>Rules are evaluated in {@link Ordered order}. A rule should return
 * {@link FetchMetadataRuleResult#UNKNOWN} when it does not apply so another rule can decide.
 * Custom rules can override {@link #getOrder()} to select their position relative to the
 * built-in policy rules.</p>
 *
 * @param <T> request type
 * @since 5.4.0
 */
public interface FetchMetadataRule<T> extends Ordered {
    /**
     * Evaluates a request.
     *
     * @param request the request to evaluate
     * @return the rule result
     */
    FetchMetadataRuleResult check(T request);
}
