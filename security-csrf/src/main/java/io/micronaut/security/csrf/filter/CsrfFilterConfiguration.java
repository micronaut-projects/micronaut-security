/*
 * Copyright 2017-2024 original authors
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
package io.micronaut.security.csrf.filter;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.util.Toggleable;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.MediaType;
import java.util.Set;

/**
 * @author Sergio del Amo
 * @since 4.11.0
 */
public interface CsrfFilterConfiguration extends Toggleable {

    /**
     *
     * @return Regular expression pattern. Filter will only process requests whose path matches this pattern.
     */
    @NonNull
    String getRegexPattern();

    /**
     *
     * @return HTTP methods. Filter will only process requests whose method matches any of these methods.
     */
    @NonNull
    Set<HttpMethod> getMethods();

    /**
     *
     * @return HTTP methods. Filter will only process requests whose content type matches any of these content types.
     */
    @NonNull
    Set<MediaType> getContentTypes();
}
