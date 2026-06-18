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
import io.micronaut.core.util.SupplierUtil;
import io.micronaut.http.context.ServerRequestContext;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.context.SecurityContext;
import io.micronaut.security.context.SecurityContextHolder;
import oracle.jdbc.EndUserSecurityContext;

import oracle.jdbc.provider.resource.AbstractResourceProvider;
import oracle.jdbc.provider.resource.ResourceParameter;
import oracle.jdbc.spi.EndUserSecurityContextProvider;
import oracle.sql.json.OracleJsonFactory;
import oracle.sql.json.OracleJsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.function.Supplier;

/**
 * OJDBC end user security context provider backed by Micronaut Security.
 *
 * @since 5.1.0
 */
@Experimental
@Internal
public final class MicronautEndUserSecurityContextProvider extends AbstractResourceProvider implements EndUserSecurityContextProvider {
    static final String DEFAULT_ROLE_PREFIX = "ORACLE_DATA_ROLE_";
    static final String DEFAULT_ATTRIBUTE_NAMES = "ORACLE_CONTEXT_ATTRIBUTES";

    /**
     * Comma separated list of data roles for an end user.
     */
    static final ResourceParameter DATA_ROLES_PARAMETER = new ResourceParameter("dataRoles", null, false, false,
            (value, parameterSetBuilder) -> { });

    /**
     * JSON object containing a fixed set of end user context attributes.
     */
    static final ResourceParameter END_USER_CONTEXT_ATTRIBUTE_PARAMETER = new ResourceParameter("endUserContextAttributes", null, false, false,
            (value, parameterSetBuilder) -> { });

    /**
     * Role prefix used to map Micronaut roles to Oracle Database data roles.
     */
    static final ResourceParameter ROLE_PREFIX_PARAMETER = new ResourceParameter("rolePrefix", DEFAULT_ROLE_PREFIX, false, false,
            (value, parameterSetBuilder) -> { });

    /**
     * Authentication attribute names used to map Micronaut authentication attributes to Oracle Database END USER CONTEXT attributes.
     */
    static final ResourceParameter ATTRIBUTE_NAMES_PARAMETER = new ResourceParameter("attributeNames", DEFAULT_ATTRIBUTE_NAMES, false, false,
            (value, parameterSetBuilder) -> { });

    /**
     * Token endpoint URL used to fetch the database access token.
     */
    static final ResourceParameter TOKEN_URL_PARAMETER = new ResourceParameter("tokenUrl", null, true, false,
            (value, parameterSetBuilder) -> { });

    /**
     * Optional OAuth 2.0 scope used to fetch the database access token.
     */
    static final ResourceParameter SCOPE_PARAMETER = new ResourceParameter("scope", null, false, false,
            (value, parameterSetBuilder) -> { });

    /**
     * Client identifier used to fetch the database access token.
     */
    static final ResourceParameter CLIENT_ID_PARAMETER = new ResourceParameter("clientId", null, true, false,
            (value, parameterSetBuilder) -> { });

    /**
     * Client secret used to fetch the database access token.
     */
    static final ResourceParameter CLIENT_SECRET_PARAMETER = new ResourceParameter("clientSecret", null, true, true,
            (value, parameterSetBuilder) -> { });

    private static final Logger LOG = LoggerFactory.getLogger(MicronautEndUserSecurityContextProvider.class);

    /**
     * Factory for creating Oracle JSON passed to
     * {@link EndUserSecurityContext#withAttributes(Map)}.
     */
    private static final OracleJsonFactory JSON_FACTORY = new OracleJsonFactory();

    private static final ResourceParameter[] PARAMETERS = {
            TOKEN_URL_PARAMETER,
            CLIENT_ID_PARAMETER,
            CLIENT_SECRET_PARAMETER,
            SCOPE_PARAMETER,
            DATA_ROLES_PARAMETER,
            END_USER_CONTEXT_ATTRIBUTE_PARAMETER,
            ROLE_PREFIX_PARAMETER,
            ATTRIBUTE_NAMES_PARAMETER,
    };

    private final DatabaseAccessTokenFetcher databaseAccessTokenFetcher;
    private final DataRolesFetcher dataRolesFetcher;
    private final AttributesFetcher attributesFetcher;

    /**
     * This public no-arg constructor is required by {@link java.util.ServiceLoader}.
     *
     * @since 5.1.0
     */
    public MicronautEndUserSecurityContextProvider() {
        this(new ClientCredentialsClientDatabaseAccessTokenFetcher(), new DefaultDataRolesFetcher(), new DefaultAttributesFetcher(JSON_FACTORY));
    }

    /**
     * Creates a Micronaut-backed OJDBC end user security context provider.
     *
     * @param databaseAccessTokenFetcher database access token fetcher
     * @param dataRolesFetcher data roles fetcher
     * @param attributesFetcher END USER CONTEXT attributes fetcher
     * @since 5.1.0
     */
    MicronautEndUserSecurityContextProvider(DatabaseAccessTokenFetcher databaseAccessTokenFetcher,
                                                   DataRolesFetcher dataRolesFetcher,
                                                   AttributesFetcher attributesFetcher) {
        super("micronaut", "end-user-security-context", PARAMETERS);
        this.databaseAccessTokenFetcher = databaseAccessTokenFetcher;
        this.dataRolesFetcher = dataRolesFetcher;
        this.attributesFetcher = attributesFetcher;
    }

    @Override
    public EndUserSecurityContext getEndUserSecurityContext(Map<Parameter, CharSequence> parameters) {
        Supplier<String> requestInfo = SupplierUtil.memoized(() -> ServerRequestContext.currentRequest().map(req -> req.getMethod() + " " + req.getPath()).orElse("No Request"));
        if (LOG.isTraceEnabled()) {
            LOG.trace("{} - resolving end user security context", requestInfo.get());
        }
        SecurityContext securityContext = SecurityContextHolder.getSecurityContext();
        Authentication authentication = securityContext.getAuthentication();
        if (authentication == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("{} - end user security context is null because authentication is null", requestInfo.get());
            }
            return null;
        }
        String databaseAccessToken = databaseAccessTokenFetcher.fetchDatabaseAccessToken(parameters);
        if (LOG.isTraceEnabled()) {
            LOG.trace("{} - end user security context resolution - resolved the database access token", requestInfo.get());
        }
        String token = securityContext.getToken();
        EndUserSecurityContext endUserSecurityContext =
            token != null
            ? EndUserSecurityContext.createWithToken(databaseAccessToken, token)
            : EndUserSecurityContext.createWithName(databaseAccessToken, authentication.getName());
        Collection<String> dataRoles = dataRolesFetcher.fetchDataRoles(parameters, authentication);
        if (dataRoles != null) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("{} - end user security context resolution - resolved the data roles {}", requestInfo.get(), dataRoles);
            }
            endUserSecurityContext = endUserSecurityContext.withDataRoles(dataRoles);
        }
        Map<String, OracleJsonObject> attributes = attributesFetcher.fetchAttributes(parameters, authentication);
        if (attributes != null) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("{} - end user security context resolution - resolved the attributes {}", requestInfo.get(), attributes);
            }
            endUserSecurityContext = endUserSecurityContext.withAttributes(attributes);
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("{} - end user security context resolved with data roles {} and attributes {}",
                requestInfo.get(),
                dataRoles != null ? dataRoles : Collections.emptyList(),
                attributes != null ? attributes : Collections.emptyMap());
        }
        return endUserSecurityContext;
    }
}
