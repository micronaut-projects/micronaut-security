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
 * A physical mailing address associated with a SCIM User.
 *
 * @param formatted The formatted mailing address
 * @param streetAddress The street address
 * @param locality The city or locality
 * @param region The state or region
 * @param postalCode The postal code
 * @param country The ISO 3166-1 alpha-2 country code
 * @param type A label describing the address's function
 * @param primary Whether this is the preferred address
 * @since 5.4.0
 */
@Serdeable
@Experimental
public record Address(
    @Nullable String formatted,
    @Nullable String streetAddress,
    @Nullable String locality,
    @Nullable String region,
    @Nullable String postalCode,
    @Nullable String country,
    @Nullable String type,
    @Nullable Boolean primary
) {
}
