/*
 * Copyright 2017-2025 original authors
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

import io.micronaut.http.context.ServerRequestContext;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.context.SecurityContext;
import io.micronaut.security.context.SecurityContextHolder;
import oracle.jdbc.EndUserSecurityContext;
import oracle.jdbc.spi.EndUserSecurityContextProvider;
import oracle.sql.json.OracleJsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

/**
 * Oracle JDBC {@link EndUserSecurityContextProvider} backed by the current
 * Micronaut Security {@link SecurityContext}.
 *
 * <p>The Oracle JDBC driver discovers this provider through {@link java.util.ServiceLoader}
 * and calls it before database operations that require an {@link EndUserSecurityContext}.
 * The provider reads the authentication and token associated with the current Micronaut
 * server request and adapts them to Oracle JDBC's end-user security context model.</p>
 *
 * <p>If no server request or authenticated user is associated with the current execution,
 * the provider returns {@code null}.</p>
 *
 * @since 5.1.0
 */
public class MicronautEndUserSecurityContextProvider implements EndUserSecurityContextProvider {
    private static final Logger LOG = LoggerFactory.getLogger(MicronautEndUserSecurityContextProvider.class);
    private static final String SYSTEM = "micronaut";
    private static final String VALUE_TYPE = "end-user-security-context";

    /**
     * Builds an Oracle JDBC end-user security context from the current Micronaut Security context.
     *
     * @param map provider parameters supplied by Oracle JDBC
     * @return an {@link EndUserSecurityContext} for the current authenticated user, or {@code null}
     * when no request or authentication is available
     */
    @Override
    public EndUserSecurityContext getEndUserSecurityContext(Map<Parameter, CharSequence> map) {
        if (ServerRequestContext.currentRequest().isEmpty()) {
            LOG.trace("no request returning null for EndUserSecurityContextProvider");
            return null;
        }
        SecurityContext securityContext = SecurityContextHolder.getSecurityContext();
        Authentication authentication = securityContext.getAuthentication();
        if (authentication == null) {
            LOG.trace("Authentication object is null");
            return null;
        }
        CharSequence databaseAccessToken = ""; //TODO
        CharSequence endUserToken = securityContext.getToken();
        Collection<String> dataRoles = Collections.emptyList();
        Map<String, OracleJsonObject> attributes = Collections.emptyMap();
        return endUserSecurityContext(databaseAccessToken, endUserToken, dataRoles, attributes);
    }

    /**
     * @return the provider name used by Oracle JDBC resource-provider configuration
     */
    @Override
    public String getName() {
        return "ojdbc-provider-" + SYSTEM + "-" + VALUE_TYPE;
    }

    /**
     * Creates an Oracle JDBC end-user security context with token, data roles, and namespace attributes.
     *
     * @param databaseAccessToken database access token used by Oracle JDBC
     * @param endUserToken token representing the authenticated Micronaut user
     * @param dataRoles Oracle data roles to activate for the end user
     * @param namespaceAttributes Oracle JSON namespace attributes to attach to the context
     * @return an immutable {@link EndUserSecurityContext}
     */
    private static EndUserSecurityContext endUserSecurityContext(
            CharSequence databaseAccessToken,
            CharSequence endUserToken,
            Collection<String> dataRoles,
            Map<String, OracleJsonObject> namespaceAttributes) {
        return EndUserSecurityContext.createWithToken(databaseAccessToken, endUserToken)
                .withDataRoles(dataRoles)
                .withAttributes(namespaceAttributes);
    }
}
