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
package io.micronaut.security.aot;

import com.squareup.javapoet.JavaFile;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.naming.Named;

/**
 * A generated file.
 * @author Sergio del Amo
 * @since 3.9.0
 */
@Internal
public class GeneratedFile implements Named {

    @NonNull
    private final String name;

    @NonNull
    private final String simpleName;

    @NonNull
    private final JavaFile javaFile;

    /**
     *
     * @param name The name qualifier
     * @param simpleName The simple filename
     * @param javaFile The java file
     */
    public GeneratedFile(@NonNull String name,
                         @NonNull String simpleName,
                         @NonNull JavaFile javaFile) {
        this.name = name;
        this.simpleName = simpleName;
        this.javaFile = javaFile;
    }

    /**
     *
     * @return The name qualifier
     */
    @Override
    @NonNull
    public String getName() {
        return name;
    }

    /**
     *
     * @return The simple filename
     */
    @NonNull
    public String getSimpleName() {
        return simpleName;
    }

    /**
     *
     * @return The java file
     */
    @NonNull
    public JavaFile getJavaFile() {
        return javaFile;
    }
}
