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
import io.micronaut.core.util.StringUtils;
import oracle.jdbc.spi.OracleResourceProvider;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.Map;

/**
 * Utility methods for reading parameters supplied to an {@link OracleResourceProvider}.
 *
 * <p>OJDBC supplies provider configuration as a map keyed by
 * {@link OracleResourceProvider.Parameter}. These helpers centralize the conversion from
 * {@link CharSequence} values to strings and the validation used by providers that require
 * specific parameters to be present.
 */
@Experimental
@Internal
public final class OracleResourceProviderParameterUtils {
    private OracleResourceProviderParameterUtils() {
    }

    /**
     * Returns the configured string value for a required provider parameter.
     *
     * <p>A parameter is considered missing when it is absent from the map or when its string
     * value is blank according to {@link String#isBlank()}. Non-blank values are returned
     * unchanged; this method does not trim or otherwise normalize the configured value.
     *
     * @param parameters parameters supplied by OJDBC
     * @param parameter parameter whose configured value is required
     *
     * @return the configured value converted to a string
     *
     * @throws IllegalStateException if the parameter is absent or blank
     */
    public static @NonNull String requiredParameter(
            @NonNull Map<OracleResourceProvider.Parameter, CharSequence> parameters,
            OracleResourceProvider.@NonNull Parameter parameter) {

        String value = optionalParameter(parameters, parameter);
        if (StringUtils.isEmpty(value)) {
            throw new IllegalStateException("Missing required provider parameter: " + parameter.name());
        }
        return value;
    }

    /**
     * Returns the configured string value for an optional provider parameter.
     *
     * <p>Absent parameters return {@code null}. Present values are converted with
     * {@link CharSequence#toString()} and returned unchanged, including blank values.
     * Callers decide whether a blank optional value should be accepted or ignored.
     *
     * @param parameters parameters supplied by OJDBC
     * @param parameter parameter whose configured value should be read
     *
     * @return the configured value converted to a string, or {@code null} when absent
     */
    public static @Nullable String optionalParameter(
            @NonNull Map<OracleResourceProvider.Parameter, CharSequence> parameters,
            OracleResourceProvider.@NonNull Parameter parameter) {

        CharSequence value = parameters.get(parameter);
        return value == null ? null : value.toString();
    }
}
