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
/**
 * Content Security Policy support for Micronaut applications.
 *
 * <p>The module adds an opt-out server filter that writes a restrictive response header and makes
 * a per-request script nonce available to supported view models. Configure the policy under
 * {@code micronaut.security.csp}. Directive-specific configuration lives in
 * {@code io.micronaut.security.csp.conf}, with each source-list directive owning a dedicated
 * configuration namespace such as {@code micronaut.security.csp.img-src}.</p>
 *
 * <p>The default policy is intentionally restrictive. Applications should begin with report-only
 * mode when adopting CSP, then explicitly enable only the sources and keyword expressions required
 * by their pages. Nonce- and hash-based script or style policies are preferred over URL allowlists.</p>
 *
 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP">Content Security Policy (CSP)</a>
 * @since 5.4.0
 */
@NullMarked
@Configuration
@Requires(property = "micronaut.security.csp.enabled", value = StringUtils.TRUE, defaultValue = StringUtils.TRUE)
package io.micronaut.security.csp;

import io.micronaut.context.annotation.Configuration;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import org.jspecify.annotations.NullMarked;
