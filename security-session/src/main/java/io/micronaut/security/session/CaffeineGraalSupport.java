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
package io.micronaut.security.session;

import io.micronaut.core.annotation.Experimental;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.TypeHint;

/**
 * Placeholder class to generate the meta-information needed by GraalVM.
 *
 * @author Iván López
 * @since 1.3.2
 */

@TypeHint(
        typeNames = {
                "io.micronaut.caffeine.cache.SSLA",
                "io.micronaut.caffeine.cache.PSW"
        },
        accessType = TypeHint.AccessType.ALL_DECLARED_CONSTRUCTORS
)
@Internal
@Experimental
public class CaffeineGraalSupport {
}
