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

import io.micronaut.context.annotation.Property;
import io.micronaut.core.util.StringUtils;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Disables the default CSP directives so a test can assert a focused directive policy.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Property(name = "micronaut.security.csp.report-only", value = StringUtils.FALSE)
@Property(name = "micronaut.security.csp.base-uri-enabled", value = StringUtils.FALSE)
@Property(name = "micronaut.security.csp.connect-src-enabled", value = StringUtils.FALSE)
@Property(name = "micronaut.security.csp.fenced-frame-src-enabled", value = StringUtils.FALSE)
@Property(name = "micronaut.security.csp.font-src-enabled", value = StringUtils.FALSE)
@Property(name = "micronaut.security.csp.object-src-enabled", value = StringUtils.FALSE)
@Property(name = "micronaut.security.csp.prefetch-src-enabled", value = StringUtils.FALSE)
@Property(name = "micronaut.security.csp.require-trusted-types-for-enabled", value = StringUtils.FALSE)
@Property(name = "micronaut.security.csp.frame-ancestors-enabled", value = StringUtils.FALSE)
@Property(name = "micronaut.security.csp.frame-src-enabled", value = StringUtils.FALSE)
@Property(name = "micronaut.security.csp.img-src-enabled", value = StringUtils.FALSE)
@Property(name = "micronaut.security.csp.manifest-src-enabled", value = StringUtils.FALSE)
@Property(name = "micronaut.security.csp.media-src-enabled", value = StringUtils.FALSE)
@Property(name = "micronaut.security.csp.form-action-enabled", value = StringUtils.FALSE)
@Property(name = "micronaut.security.csp.script-src-nonce-enabled", value = StringUtils.FALSE)
@Property(name = "micronaut.security.csp.script-src-strict-dynamic", value = StringUtils.FALSE)
@Property(name = "micronaut.security.csp.style-src-enabled", value = StringUtils.FALSE)
@Property(name = "micronaut.security.csp.worker-src-enabled", value = StringUtils.FALSE)
@interface DisableCspDefaults {
}
