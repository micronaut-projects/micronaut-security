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
import io.micronaut.core.annotation.Internal;
import io.micronaut.inject.annotation.NamedAnnotationMapper;
import io.micronaut.inject.visitor.VisitorContext;
import io.micronaut.security.annotation.RunAsAuthentication;
import io.micronaut.security.annotation.RunAsUser;

import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Maps {@link RunAsUser} to {@link RunAsAuthentication}.
 */
@Internal
public class RunAsUserAnnotationMapper implements NamedAnnotationMapper {

    private static final String MEMBER_NAME = "name";
    private static final String MEMBER_ROLES = "roles";
    private static final String ROLES_KEY = "roles";

    @Override
    public String getName() {
        return RunAsUser.class.getName();
    }

    @Override
    public List<AnnotationValue<?>> map(AnnotationValue<Annotation> annotation, VisitorContext visitorContext) {
        try {
            return map(authenticationJson(annotation));
        } catch (RunAsUserAnnotationMapperException e) {
            visitorContext.fail(e.getMessage(), null);
            return List.of();
        }
    }

    private static List<AnnotationValue<?>> map(String json) {
        List<AnnotationValue<?>> annotationValues = new ArrayList<>(1);
        annotationValues.add(AnnotationValue.builder(RunAsAuthentication.class).value(json).build());
        return annotationValues;
    }

    private static String authenticationJson(AnnotationValue<Annotation> annotation) {
        String value = annotation.stringValue().orElse("");
        String name = annotation.stringValue(MEMBER_NAME).orElse("");
        String username = resolveUsername(value, name);
        if (username == null) {
            throw new RunAsUserAnnotationMapperException("@RunAsUser username cannot be null");
        }
        String[] roles = annotation.stringValues(MEMBER_ROLES);
        for (String role : roles) {
            if (role.isBlank()) {
                throw new RunAsUserAnnotationMapperException("@RunAsUser roles cannot contain blank values");
            }
        }
        return authenticationJson(username, roles);
    }

    private static String resolveUsername(String value, String name) {
        if (value.isBlank() && name.isBlank()) {
            throw new RunAsUserAnnotationMapperException("@RunAsUser requires either value or name");
        }
        if (!value.isBlank() && !name.isBlank() && !value.equals(name)) {
            throw new RunAsUserAnnotationMapperException("@RunAsUser value and name must match when both are specified");
        }
        return value.isBlank() ? name : value;
    }

    private static String authenticationJson(String username, String[] roles) {
        StringBuilder json = new StringBuilder();
        json.append("{\"name\":\"")
            .append(escapeJson(username))
            .append('"');
        if (roles.length > 0) {
            json.append(",\"attributes\":{\"rolesKey\":\"")
                .append(ROLES_KEY)
                .append("\",\"roles\":[");
            for (int i = 0; i < roles.length; i++) {
                if (i > 0) {
                    json.append(',');
                }
                json.append('"')
                    .append(escapeJson(roles[i]))
                    .append('"');
            }
            json.append("]}");
        }
        json.append('}');
        return json.toString();
    }

    private static String escapeJson(String value) {
        StringBuilder escaped = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char character = value.charAt(i);
            switch (character) {
                case '"' -> escaped.append("\\\"");
                case '\\' -> escaped.append("\\\\");
                case '\b' -> escaped.append("\\b");
                case '\f' -> escaped.append("\\f");
                case '\n' -> escaped.append("\\n");
                case '\r' -> escaped.append("\\r");
                case '\t' -> escaped.append("\\t");
                default -> {
                    if (character < 0x20) {
                        escaped.append(String.format(Locale.ROOT, "\\u%04x", (int) character));
                    } else {
                        escaped.append(character);
                    }
                }
            }
        }
        return escaped.toString();
    }

    private static class RunAsUserAnnotationMapperException extends RuntimeException {
        RunAsUserAnnotationMapperException(String message) {
            super(message);
        }
    }
}
