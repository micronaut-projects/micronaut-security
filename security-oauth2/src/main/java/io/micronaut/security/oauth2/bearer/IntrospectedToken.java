/*
 * Copyright 2017-2019 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.micronaut.security.oauth2.bearer;

import io.micronaut.security.authentication.Authentication;

import javax.annotation.Nonnull;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents introspection information of oauth token received from authorization service.
 *
 * @author svishnyakoff
 * @since 1.3.0
 */
public final class IntrospectedToken implements Authentication {

    private static final IntrospectedToken INACTIVE_TOKEN = new IntrospectedToken(false, "", Collections.emptyList(), 0, 0,
                                                                                  Collections.emptyMap());
    private final boolean isActive;
    private final String username;
    private final int iat;
    private final int exp;
    private final Map<String, Object> attributes;

    /**
     *
     * @param isActive flag that tells if token is active. If it is expired or fetching failed, the flag should be false
     * @param username user name token is issued for
     * @param scopes token scopes
     * @param tokenIssuingTime time when token was issued in seconds
     * @param tokenExpirationTime time when token expire
     * @param attributes all the introspection data received from authorization service
     */
    private IntrospectedToken(boolean isActive, String username, List<String> scopes, int tokenIssuingTime,
                              int tokenExpirationTime, Map<String, Object> attributes) {
        this.isActive = isActive;
        this.username = username;
        this.iat = tokenIssuingTime;
        this.exp = tokenExpirationTime;

        Map<String, Object> attr = new HashMap<>();
        attr.putAll(attributes);
        attr.put("roles", scopes);
        this.attributes = Collections.unmodifiableMap(attr);
    }


    /**
     * Create valid active token.
     *
     * @param username user name token is issued for
     * @param scopes token scopes
     * @param tokenIssuingTime time when token was issued in seconds
     * @param tokenExpirationTime time when token expire
     * @param attributes all the introspection data received from authorization service
     * @return Active token
     */
    public static IntrospectedToken createActiveAuthentication(String username, List<String> scopes, int tokenIssuingTime,
                                                               int tokenExpirationTime,
                                                               Map<String, Object> attributes) {
        return new IntrospectedToken(true, username, scopes, tokenIssuingTime, tokenExpirationTime, attributes);
    }

    /**
     * @return inactive token.
     */
    public static IntrospectedToken createInactiveAuthentication() {
        return INACTIVE_TOKEN;
    }

    @Nonnull
    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public String getName() {
        return username;
    }

    /**
     * @return true if token is valid and considered valid by authorization service. False otherwise, e.g. token expired,
     * token is not recognized by authorization service, request to auth service failed.
     */
    public boolean isActive() {
        return isActive;
    }

    /**
     * @return Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token was
     * originally issued
     */
    public int getTokenIssueTime() {
        return this.iat;
    }

    /**
     * @return Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token expire
     */
    public int getTokenExpirationTime() {
        return this.exp;
    }
}
