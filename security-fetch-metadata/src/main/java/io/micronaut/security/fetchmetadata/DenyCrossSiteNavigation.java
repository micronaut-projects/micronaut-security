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

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a route method that a navigation started by another site must not reach.
 *
 * <p>The built-in simple navigation rule allows {@code GET} navigations from any site. For a
 * route annotated with {@code DenyCrossSiteNavigation}, it does not: a cross-site navigation,
 * for example a link or a script on another site that sends the browser to the route, is
 * rejected with {@code 403 Forbidden} unless another rule allows it. Same-origin navigations,
 * navigations the user starts from the browser UI ({@code Sec-Fetch-Site: none}), and requests
 * without Fetch Metadata are still allowed by the rules that run before the navigation rule,
 * as long as those rules are enabled. A same-site navigation is allowed only when same-site
 * requests are allowed.</p>
 *
 * <p>Annotate a {@code GET} route whose side effects must only be triggered from the
 * application itself, such as a route that starts a login. Micronaut Security OAuth 2.0
 * annotates its login route with it. The property
 * {@code micronaut.security.fetch-metadata.rules.deny-annotated-cross-site-navigation}
 * switches this protection off.</p>
 *
 * <p>The annotation applies to route methods only, by design; it cannot be placed on a
 * controller class. It only matters for {@code GET} routes: cross-site requests with other
 * methods are not allowed by the simple navigation rule in any case.</p>
 *
 * <p>Micronaut copies this annotation to a method that implements or overrides an annotated
 * method, as long as this module is on the compile classpath of the implementing class.
 * Otherwise, repeat the annotation.</p>
 *
 * @since 5.6.0
 */
@Documented
@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface DenyCrossSiteNavigation {
}
