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

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Applies a run-as authentication for the supplied user name and roles to
 * intercepted method invocations.
 *
 * <p>Micronaut Security maps this annotation at compilation time to
 * {@link RunAsAuthentication}. Use {@link RunAsAuthentication} directly when
 * the run-as authentication needs custom attributes.</p>
 *
 * @author Sergio del Amo
 * @since 5.1.0
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface RunAsUser {

    /**
     * Shortcut for {@link #name()}.
     *
     * @return The user name for the run-as authentication
     */
    String value() default "";

    /**
     * @return The user name for the run-as authentication
     */
    String name() default "";

    /**
     * @return The roles for the run-as authentication
     */
    String[] roles() default {};
}
