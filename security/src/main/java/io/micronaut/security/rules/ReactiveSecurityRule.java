/*
 * Copyright 2017-2020 original authors
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

import edu.umd.cs.findbugs.annotations.Nullable;
import io.micronaut.core.order.Ordered;
import io.micronaut.http.HttpRequest;
import io.micronaut.web.router.RouteMatch;
import org.reactivestreams.Publisher;

import java.util.Map;

/**
 * Informs the JWT filter what to do with the given request. Use this if your SecurityRule needs to
 * do any blocking work.
 *
 * @author Steven Brown
 * @since 2.4
 */
public interface ReactiveSecurityRule extends Ordered {
  /**
   * Returns a flowable of security result based on conditions.
   *
   * @param request The current request
   * @param routeMatch The matched route or empty if no route was matched. e.g. static resource.
   * @param claims The claims from the token. Null if not authenticated
   * @return Flowable containing the SecurityRuleResult (allowed or rejected) or empty flowable on
   *     Unknown
   * @see SecurityRuleResult
   */
  Publisher<SecurityRuleResult> check(HttpRequest<?> request, @Nullable RouteMatch<?> routeMatch, @Nullable Map<String, Object> claims);
}
