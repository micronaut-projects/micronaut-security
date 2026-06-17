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
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.DATA_ROLES_PARAMETER;
import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.ROLE_PREFIX_PARAMETER;

/**
 * Default {@link DataRolesFetcher} implementation.
 *
 * @since 5.1.0
 */
@Experimental
@Internal
class DefaultDataRolesFetcher implements DataRolesFetcher {

    /**
     * Creates a default data roles fetcher.
     *
     * @since 5.1.0
     */
    DefaultDataRolesFetcher() {
    }

    @Override
    public @Nullable Collection<String> fetchDataRoles(@NonNull Map<OracleResourceProvider.Parameter, CharSequence> parameters,
                                                       @NonNull Authentication authentication) {
        return mergeDataRoles(getFixedDataRoles(parameters), getRolePrefixDataRoles(parameters, authentication));
    }

    /**
     * Returns DATA ROLE names derived from roles that begin with the prefix
     * configured by {@link MicronautEndUserSecurityContextProvider#ROLE_PREFIX_PARAMETER}.
     *
     * @param parameters Parameters that configure this provider. Not null, may
     * not contain null.
     *
     * @return Set of DATA ROLEs to enable. Not null, may not contain null.
     */
    private static Set<String> getRolePrefixDataRoles(Map<OracleResourceProvider.Parameter, CharSequence> parameters, Authentication authentication) {
        CharSequence prefix = parameters.get(ROLE_PREFIX_PARAMETER);
        if (prefix == null) {
            return Collections.emptySet();
        }
        return RolesUtils.getPrefixedRoles(prefix.toString(), authentication);
    }

    /**
     * Merges data role sets into a single set.
     *
     * @param dataRoleSets data role sets to merge
     * @return merged data roles, or {@code null} when every set is empty or {@code null}
     * @since 5.1.0
     */
    @SafeVarargs
    public static @Nullable Set<String> mergeDataRoles(Set<String>... dataRoleSets) {
        HashSet<String> merged = null;
        for (Set<String> dataRoles : dataRoleSets) {
            if (dataRoles == null || dataRoles.isEmpty()) {
                continue;
            }
            if (merged == null) {
                merged = new HashSet<>(dataRoles);
            } else {
                merged.addAll(dataRoles);
            }
        }
        return merged;
    }

    /**
     * Returns DATA ROLE names configured by the {@link MicronautEndUserSecurityContextProvider#DATA_ROLES_PARAMETER}.
     *
     * @param parameters Parameters that configure this provider. Not null, may
     * not contain null.
     *
     *
     * @return Set of DATA ROLEs to enable. Not null, may not contain null.
     */
    private static Set<String> getFixedDataRoles(Map<OracleResourceProvider.Parameter, CharSequence> parameters) {
        CharSequence fixedDataRoles = parameters.get(DATA_ROLES_PARAMETER);
        if (fixedDataRoles == null) {
            return Collections.emptySet();
        }
        return Arrays.stream(fixedDataRoles.toString().split(","))
                .map(String::trim)
                .filter(dataRole -> !dataRole.isEmpty())
                .collect(Collectors.toUnmodifiableSet());
    }
}
