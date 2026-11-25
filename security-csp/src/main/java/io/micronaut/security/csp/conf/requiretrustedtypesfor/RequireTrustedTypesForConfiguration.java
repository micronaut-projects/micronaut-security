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
package io.micronaut.security.csp.conf.requiretrustedtypesfor;

import io.micronaut.core.util.Toggleable;

/**
 * Configuration for the {@code require-trusted-types-for} directive, which makes browsers reject
 * strings assigned to DOM injection sinks unless they come from a Trusted Types policy.
 *
 * @since 5.6.0
 */
public interface RequireTrustedTypesForConfiguration extends Toggleable {
    /**
     * Returns the Trusted Types sink group written in the directive.
     *
     * @return the sink group, such as {@code 'script'}, including its single quotes
     */
    String getValue();
}
