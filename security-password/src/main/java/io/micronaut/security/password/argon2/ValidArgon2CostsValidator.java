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

import io.micronaut.core.annotation.AnnotationValue;
import io.micronaut.core.annotation.Internal;
import io.micronaut.validation.validator.constraints.ConstraintValidator;
import io.micronaut.validation.validator.constraints.ConstraintValidatorContext;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;

import static io.micronaut.security.password.argon2.Argon2PhcString.MEMORY_PER_LANE;

/**
 * Validates {@link ValidArgon2Costs}, reporting a violation for each property that is outside its
 * limits.
 *
 * @since 5.5.0
 */
@Singleton
@Internal
final class ValidArgon2CostsValidator implements ConstraintValidator<ValidArgon2Costs, Argon2PasswordEncoderConfiguration> {

    @Override
    public boolean isValid(@Nullable Argon2PasswordEncoderConfiguration configuration,
                           AnnotationValue<ValidArgon2Costs> annotationMetadata,
                           ConstraintValidatorContext context) {
        if (configuration == null) {
            return true;
        }
        // an invalid parallelism is reported by its own constraint
        long minMemory = (long) MEMORY_PER_LANE * Math.max(1, configuration.getParallelism());
        int maxMemory = configuration.getMaxMemory();
        int maxIterations = configuration.getMaxIterations();
        boolean memoryValid = configuration.getMemory() >= minMemory && configuration.getMemory() <= maxMemory;
        boolean iterationsValid = configuration.getIterations() <= maxIterations;
        if (memoryValid && iterationsValid) {
            return true;
        }
        // only when invalid: the validator does not reset the flag after a valid constraint
        context.disableDefaultConstraintViolation();
        if (!memoryValid) {
            addViolation(context, "memory", "must be between " + minMemory + " and " + maxMemory);
        }
        if (!iterationsValid) {
            addViolation(context, "iterations", "must be less than or equal to " + maxIterations);
        }
        return false;
    }

    private static void addViolation(ConstraintValidatorContext context, String property, String message) {
        context.buildConstraintViolationWithTemplate(message)
            .addPropertyNode(property)
            .addConstraintViolation();
    }
}
