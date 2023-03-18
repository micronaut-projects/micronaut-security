/*
 * Copyright 2017-2023 original authors
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
package io.micronaut.security.rules;

import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.order.Ordered;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.web.router.RouteMatch;
import org.reactivestreams.Publisher;

/**
 * Informs the {@link io.micronaut.security.filters.SecurityFilter} filter what to do with the given request.
 *
 * @author James Kleeh
 * @since 1.0
 */
public interface SecurityRule extends Ordered {

    /**
     * The token to represent allowing anonymous access.
     */
    String IS_ANONYMOUS = "isAnonymous()";

    /**
     * The token to represent allowing any authenticated access.
     */
    String IS_AUTHENTICATED = "isAuthenticated()";

    /**
     * The token to represent no security roles are allowed.
     */
    String DENY_ALL = "denyAll()";

    /**
     * Returns a publisher that is required to emit a single security result
     * based on any conditions.
     * @see SecurityRuleResult
     *
     * @param request The current request
     * @param routeMatch The matched route or empty if no route was matched. e.g. static resource.
     * @param authentication The user authentication. Null if not authenticated
     * @return The result
     */
    Publisher<SecurityRuleResult> check(HttpRequest<?> request, @Nullable RouteMatch<?> routeMatch, @Nullable Authentication authentication);
}
