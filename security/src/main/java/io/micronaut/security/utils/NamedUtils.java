/*
 * Copyright 2017-2022 original authors
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
package io.micronaut.security.utils;

import io.micronaut.context.Qualifier;
import io.micronaut.core.annotation.AnnotationMetadataProvider;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.naming.Named;
import io.micronaut.inject.QualifiedBeanType;

import java.util.Optional;

/**
 * Utility class to get the name qualifier value.
 * @author Sergio del Amo
 * @since 4.0.0
 */
@Internal
public class NamedUtils {
    private NamedUtils() {

    }

    /**
     *
     * @param component Component
     * @return the name qualifier if any
     */
    @NonNull
    public static Optional<String> nameQualifier(@NonNull AnnotationMetadataProvider component) {
        if (component instanceof QualifiedBeanType<?> qualifiedBeanType) {
            Qualifier<?> declaredQualifier = qualifiedBeanType.getDeclaredQualifier();
            if (declaredQualifier instanceof Named named) {
                return Optional.of(named.getName());
            }
        }
        return Optional.empty();
    }
}
