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
package io.micronaut.security.scim.core;

import io.micronaut.core.annotation.Experimental;
import io.micronaut.serde.annotation.Serdeable;
import org.jspecify.annotations.Nullable;

/**
 * Components of a SCIM User's name.
 *
 * @param formatted The full formatted name
 * @param familyName The family name
 * @param givenName The given name
 * @param middleName The middle name
 * @param honorificPrefix The honorific prefix
 * @param honorificSuffix The honorific suffix
 * @since 5.4.0
 */
@Serdeable
@Experimental
public record Name(
    @Nullable String formatted,
    @Nullable String familyName,
    @Nullable String givenName,
    @Nullable String middleName,
    @Nullable String honorificPrefix,
    @Nullable String honorificSuffix
) {
}
