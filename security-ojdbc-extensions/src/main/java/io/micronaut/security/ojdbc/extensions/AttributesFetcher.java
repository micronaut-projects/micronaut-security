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
package io.micronaut.security.ojdbc.extensions;

import io.micronaut.core.annotation.Experimental;
import io.micronaut.core.annotation.Internal;
import io.micronaut.security.authentication.Authentication;
import oracle.jdbc.spi.OracleResourceProvider;
import oracle.sql.json.OracleJsonObject;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.Map;

/**
 * Resolves Oracle Database END USER CONTEXT attributes for the current
 * Micronaut Security authentication.
 *
 * @since 5.1.0
 */
@Experimental
@Internal
public interface AttributesFetcher {

    /**
     * Resolves the END USER CONTEXT attributes to apply to the Oracle JDBC
     * end user security context.
     *
     * @param parameters parameters supplied to the OJDBC resource provider
     * @param authentication the current Micronaut Security authentication
     * @return the attributes to apply, or {@code null} when no attributes should be applied
     */
    @Nullable Map<String, OracleJsonObject> fetchAttributes(@NonNull Map<OracleResourceProvider.Parameter, CharSequence> parameters,
                                                            @NonNull Authentication authentication);
}
