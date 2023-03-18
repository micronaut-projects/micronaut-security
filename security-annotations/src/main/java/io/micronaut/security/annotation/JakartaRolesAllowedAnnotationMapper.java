/*
 * Copyright 2017-2023 original authors
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
package io.micronaut.security.annotation;

import io.micronaut.core.annotation.AnnotationValue;
import io.micronaut.core.annotation.Internal;
import io.micronaut.inject.annotation.NamedAnnotationMapper;
import io.micronaut.inject.visitor.VisitorContext;

import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.List;

/**
 * Allows using the {@link jakarta.annotation.security.RolesAllowed} annotation in Micronaut.
 *
 * @author Fredrik Hov
 */
@Internal
public class JakartaRolesAllowedAnnotationMapper implements NamedAnnotationMapper {
    @Override
    public String getName() {
        return "jakarta.annotation.security.RolesAllowed";
    }

    @Override
    public List<AnnotationValue<?>> map(AnnotationValue<Annotation> annotation, VisitorContext visitorContext) {
        String[] values = annotation.get("value", String[].class).orElse(new String[0]);

        List<AnnotationValue<?>> annotationValues = new ArrayList<>(1);
        annotationValues.add(
            AnnotationValue.builder(Secured.class)
                .values(values)
                .build()
        );
        return annotationValues;
    }
}
