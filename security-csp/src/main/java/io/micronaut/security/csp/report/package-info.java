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
 * Receives Content Security Policy reports delivered through the Reporting API.
 *
 * @see <a href="https://w3c.github.io/reporting/">Reporting API</a>
 */
@Requires(classes = Controller.class)
@Requires(property = ContentSecurityPolicyConfigurationProperties.PREFIX + ".enabled", value = StringUtils.TRUE, defaultValue = StringUtils.TRUE)
@Configuration
@NullMarked
package io.micronaut.security.csp.report;

import io.micronaut.context.annotation.Configuration;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.annotation.Controller;
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties;
import org.jspecify.annotations.NullMarked;
