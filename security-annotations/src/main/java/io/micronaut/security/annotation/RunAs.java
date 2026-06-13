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
package io.micronaut.security.annotation;

import io.micronaut.aop.Around;
import io.micronaut.context.annotation.AliasFor;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Applies a run-as authentication to intercepted method invocations.
 *
 * @author Sergio del Amo
 * @since 5.1.0
 */
@Around
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface RunAs {

    /**
     * Alias for {@link #roles()}.
     *
     * @return The roles for the run-as authentication
     * @since 5.1.0
     */
    @AliasFor(member = "roles")
    String[] value() default {};

    /**
     * @return The user name for the run-as authentication, or the current user name when blank
     */
    String name() default "";

    /**
     * @return The roles for the run-as authentication
     */
    @AliasFor(member = "value")
    String[] roles() default {};

    /**
     * @return Whether the supplied roles should be appended to the current authentication roles.
     * @since 5.1.0
     */
    boolean appendRoles() default true;

    /**
     * @return The attributes for the run-as authentication
     */
    Attribute[] attributes() default {};

    /**
     * @return Whether the supplied attributes should be appended to the current authentication attributes.
     * @since 5.1.0
     */
    boolean appendAttributes() default true;
}
