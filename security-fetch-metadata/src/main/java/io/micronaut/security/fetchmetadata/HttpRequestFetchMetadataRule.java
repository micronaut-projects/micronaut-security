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

import io.micronaut.http.HttpRequest;
import io.micronaut.http.SecFetch;
import org.jspecify.annotations.Nullable;

/**
 * A Fetch Metadata rule for {@link HttpRequest} instances.
 *
 * @since 5.4.0
 */
public interface HttpRequestFetchMetadataRule extends FetchMetadataRule<HttpRequest<?>> {
    /**
     * Extracts {@link SecFetch} from the request and evaluates it.
     *
     * @param request the request to evaluate
     * @return the rule result
     */
    @Override
    default FetchMetadataRuleResult check(HttpRequest<?> request) {
        return check(request, request.getSecFetch());
    }

    /**
     * Evaluates the request and its parsed Fetch Metadata headers.
     *
     * @param request the request to evaluate
     * @param secFetch parsed Fetch Metadata, or {@code null} when the required headers are absent or invalid
     * @return the rule result
     */
    FetchMetadataRuleResult check(HttpRequest<?> request, @Nullable SecFetch secFetch);
}
