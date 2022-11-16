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
package io.micronaut.security.aot;

import io.micronaut.aot.core.AOTContext;
import io.micronaut.context.Qualifier;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;

import java.util.Collection;

/**
 * Utility to retrieve beans from the Application Context associated to the AOT Context.
 * @author Sergio del Amo
 * @since 3.9.0
 */
@Internal
public final class AOTContextUtils {
    private AOTContextUtils() {

    }

    /**
     * Get all beans of the given type.
     *
     * @param beanType The bean type
     * @param <T>      The bean type parameter
     * @param aotContext The AOT Context
     * @return The found beans
     */
    @NonNull
    public static <T> Collection<T> getBeansOfType(@NonNull Class<T> beanType, @NonNull AOTContext aotContext) {
        return  aotContext.getAnalyzer()
            .getApplicationContext()
            .getBeansOfType(beanType);
    }

    /**
     * Obtains a Bean for the given type.
     *
     * @param beanType The bean type
     * @param <T>      The bean type parameter
     * @param aotContext The AOT Context
     * @return An instanceof said bean
     * @throws io.micronaut.context.exceptions.NonUniqueBeanException When multiple possible bean definitions exist
     *                                                                for the given type
     * @throws io.micronaut.context.exceptions.NoSuchBeanException If the bean doesn't exist
     */
    @NonNull
    public static <T> T getBean(@NonNull Class<T> beanType, @NonNull AOTContext aotContext) {
        return  aotContext.getAnalyzer()
            .getApplicationContext()
            .getBean(beanType);
    }

    /**
     * Return whether the bean of the given type is contained within this context.
     *
     * @param beanType  The bean type
     * @param qualifier The qualifier for the bean
     * @param <T>       The concrete type
     * @param aotContext The AOT Context
     * @return True if it is
     */
    @NonNull
    public static <T> boolean containsBean(@NonNull Class<T> beanType, @Nullable Qualifier<T> qualifier, @NonNull AOTContext aotContext) {
        return  aotContext.getAnalyzer()
            .getApplicationContext()
            .containsBean(beanType, qualifier);
    }

    /**
     * Obtains a Bean for the given type and qualifier.
     *
     * @param beanType  The bean type
     * @param qualifier The qualifier
     * @param <T>       The bean type parameter
     * @param aotContext The AOT Context
     * @return An instanceof said bean
     * @throws io.micronaut.context.exceptions.NonUniqueBeanException When multiple possible bean definitions exist
     *                                                                for the given type
     * @see io.micronaut.inject.qualifiers.Qualifiers
     */
    @NonNull
    public static <T> T getBean(@NonNull Class<T> beanType, @Nullable Qualifier<T> qualifier, @NonNull AOTContext aotContext) {
        return  aotContext.getAnalyzer()
            .getApplicationContext()
            .getBean(beanType, qualifier);
    }
}

