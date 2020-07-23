/*
 * Copyright 2017-2020 original authors
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
package io.micronaut.security.rules;

import io.micronaut.security.token.MapClaims;
import io.micronaut.security.token.RolesFinder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * A base {@link SecurityRule} class to extend from that provides
 * helper methods to get the roles from the claims and compare them
 * to the roles allowed by the rule.
 *
 * @author James Kleeh
 * @since 1.0
 */
public abstract class AbstractSecurityRule implements SecurityRule {

    private static final Logger LOG = LoggerFactory.getLogger(AbstractSecurityRule.class);

    private final RolesFinder rolesFinder;

    /**
     * @param rolesFinder Roles Parser
     */
    @Inject
    public AbstractSecurityRule(RolesFinder rolesFinder) {
        this.rolesFinder = rolesFinder;
    }

    /**
     * Appends {@link SecurityRule#IS_ANONYMOUS} if not authenticated. If the
     * claims contain one or more roles, {@link SecurityRule#IS_AUTHENTICATED} is
     * appended to the list.
     *
     * @param claims The claims of the token, null if not authenticated
     * @return The granted roles
     */
    protected List<String> getRoles(Map<String, Object> claims) {
        List<String> roles = new ArrayList<>();
        if (claims == null) {
            roles.add(SecurityRule.IS_ANONYMOUS);
        } else {
            if (!claims.isEmpty()) {
                roles.addAll(rolesFinder.findInClaims(new MapClaims(claims)));
            }
            roles.add(SecurityRule.IS_ANONYMOUS);
            roles.add(SecurityRule.IS_AUTHENTICATED);
        }

        return roles;
    }

    /**
     * Compares the given roles to determine if the request is allowed by
     * comparing if any of the granted roles is in the required roles list.
     *
     * @param requiredRoles The list of roles required to be authorized
     * @param grantedRoles The list of roles granted to the user
     * @return {@link SecurityRuleResult#REJECTED} if none of the granted roles
     *  appears in the required roles list. {@link SecurityRuleResult#ALLOWED} otherwise.
     */
    protected SecurityRuleResult compareRoles(List<String> requiredRoles, List<String> grantedRoles) {
        if (rolesFinder.hasAnyRequiredRoles(requiredRoles, grantedRoles)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("The given roles [{}] matched one or more of the required roles [{}]. Allowing the request", grantedRoles, requiredRoles);
            }
            return SecurityRuleResult.ALLOWED;
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("None of the given roles [{}] matched the required roles [{}]. Rejecting the request", grantedRoles, requiredRoles);
            }
            return SecurityRuleResult.REJECTED;
        }
    }
}
