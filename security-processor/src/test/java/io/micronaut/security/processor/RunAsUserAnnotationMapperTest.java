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
package io.micronaut.security.processor;

import io.micronaut.core.annotation.AnnotationValue;
import io.micronaut.inject.visitor.VisitorContext;
import io.micronaut.security.annotation.RunAsAuthentication;
import io.micronaut.security.annotation.RunAsUser;
import org.junit.jupiter.api.Test;

import java.lang.annotation.Annotation;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class RunAsUserAnnotationMapperTest {

    private final RunAsUserAnnotationMapper mapper = new RunAsUserAnnotationMapper();
    private final VisitorContext visitorContext = mock(VisitorContext.class);

    @Test
    void nameMatchesRunAsUserAnnotation() {
        assertEquals(RunAsUser.class.getName(), mapper.getName());
    }

    @Test
    void mapsValueToRunAsAuthentication() {
        List<AnnotationValue<?>> mapped = map(
            AnnotationValue.builder(RunAsUser.class)
                .value("sergio")
                .build()
        );

        assertEquals(1, mapped.size());
        AnnotationValue<?> annotation = mapped.get(0);
        assertEquals(RunAsAuthentication.class.getName(), annotation.getAnnotationName());
        assertEquals("{\"name\":\"sergio\"}", annotation.stringValue().orElseThrow());
        verifyNoInteractions(visitorContext);
    }

    @Test
    void mapsNameAndRolesToRunAsAuthentication() {
        List<AnnotationValue<?>> mapped = map(
            AnnotationValue.builder(RunAsUser.class)
                .member("name", "sergio")
                .member("roles", "ROLE_USER", "ROLE_ADMIN")
                .build()
        );

        assertEquals(1, mapped.size());
        AnnotationValue<?> annotation = mapped.get(0);
        assertEquals(RunAsAuthentication.class.getName(), annotation.getAnnotationName());
        assertEquals("""
                {"name":"sergio","attributes":{"rolesKey":"roles","roles":["ROLE_USER","ROLE_ADMIN"]}}""",
            annotation.stringValue().orElseThrow()
        );
        verifyNoInteractions(visitorContext);
    }

    @Test
    void escapesJsonValues() {
        List<AnnotationValue<?>> mapped = map(
            AnnotationValue.builder(RunAsUser.class)
                .member("name", "sergio \"del Amo\"")
                .member("roles", "ROLE_\\USER")
                .build()
        );

        assertEquals(1, mapped.size());
        assertEquals(
            """
            {"name":"sergio \\"del Amo\\"","attributes":{"rolesKey":"roles","roles":["ROLE_\\\\USER"]}}""",
            mapped.get(0).stringValue().orElseThrow()
        );
        verifyNoInteractions(visitorContext);
    }

    @Test
    void requiresValueOrName() {
        List<AnnotationValue<?>> mapped = map(
            AnnotationValue.builder(RunAsUser.class)
                .build()
        );

        assertTrue(mapped.isEmpty());
        verify(visitorContext).fail(eq("@RunAsUser requires either value or name"), isNull());
    }

    @Test
    void failsWhenValueAndNameDoNotMatch() {
        List<AnnotationValue<?>> mapped = map(
            AnnotationValue.builder(RunAsUser.class)
                .value("sergio")
                .member("name", "tim")
                .build()
        );

        assertTrue(mapped.isEmpty());
        verify(visitorContext).fail(eq("@RunAsUser value and name must match when both are specified"), isNull());
    }

    @Test
    void failsWhenRolesContainBlankValues() {
        List<AnnotationValue<?>> mapped = map(
            AnnotationValue.builder(RunAsUser.class)
                .member("name", "sergio")
                .member("roles", "ROLE_USER", " ")
                .build()
        );

        assertTrue(mapped.isEmpty());
        verify(visitorContext).fail(eq("@RunAsUser roles cannot contain blank values"), isNull());
    }

    @SuppressWarnings("unchecked")
    private List<AnnotationValue<?>> map(AnnotationValue<RunAsUser> annotation) {
        return mapper.map((AnnotationValue<Annotation>) (AnnotationValue<?>) annotation, visitorContext);
    }
}
