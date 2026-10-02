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
package io.micronaut.security.password.argon2;

import io.micronaut.core.annotation.Internal;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Constrains the costs of an {@link Argon2PasswordEncoderConfiguration} that depend on other
 * properties: the memory must be at least {@value Argon2PhcString#MEMORY_PER_LANE} kibibytes for
 * each degree of parallelism and at most the maximum memory, and the iterations must not exceed the
 * maximum iterations.
 *
 * @since 5.5.0
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Constraint(validatedBy = {})
@Internal
@interface ValidArgon2Costs {

    /**
     * @return the message used when the validator does not report a violation for a property
     */
    String message() default "the memory and iterations must be within their limits";

    /**
     * @return the validation groups the constraint belongs to
     */
    Class<?>[] groups() default {};

    /**
     * @return the payload associated with the constraint
     */
    Class<? extends Payload>[] payload() default {};
}
