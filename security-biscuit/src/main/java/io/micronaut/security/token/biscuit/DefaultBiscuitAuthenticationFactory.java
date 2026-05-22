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
package io.micronaut.security.token.biscuit;

import io.micronaut.context.annotation.Requires;
import io.micronaut.security.authentication.Authentication;
import jakarta.inject.Singleton;
import org.biscuitsec.biscuit.error.Error;
import org.biscuitsec.biscuit.token.builder.Fact;
import org.biscuitsec.biscuit.token.builder.Term;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static io.micronaut.security.utils.LoggingUtils.debug;

/**
 * Default Biscuit authentication factory.
 *
 * @author Sergio del Amo
 * @since 5.1.0
 */
@Requires(missingBeans = BiscuitAuthenticationFactory.class)
@Singleton
public class DefaultBiscuitAuthenticationFactory implements BiscuitAuthenticationFactory {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultBiscuitAuthenticationFactory.class);

    private final BiscuitConfiguration configuration;

    /**
     * @param configuration Biscuit configuration
     */
    public DefaultBiscuitAuthenticationFactory(BiscuitConfiguration configuration) {
        this.configuration = configuration;
    }

    @Override
    public Optional<Authentication> createAuthentication(BiscuitAuthenticationContext context) {
        try {
            Optional<String> name = principal(context);
            if (name.isEmpty()) {
                debug(LOG, "Biscuit authentication mapping failed because no principal was found");
                return Optional.empty();
            }
            Map<String, Object> attributes = new LinkedHashMap<>();
            attributes.put("biscuit.policyIndex", context.getPolicyIndex());
            attributes.put("biscuit.revocationIdentifiers", context.getRevocationIdentifiers());
            return Optional.of(Authentication.build(name.get(), roles(context), attributes));
        } catch (Error e) {
            debug(LOG, "Biscuit authentication mapping failed: {}", e.getClass().getSimpleName());
            return Optional.empty();
        }
    }

    private Optional<String> principal(BiscuitAuthenticationContext context) throws Error {
        Set<Fact> facts = context.getAuthorizer().query(configuration.getAuthentication().getPrincipalQuery(), BiscuitTokenValidator.runLimits(configuration));
        for (Fact fact : facts) {
            List<Term> terms = fact.terms();
            if (!terms.isEmpty()) {
                return Optional.of(BiscuitTermMapper.toJavaValue(terms.get(0)).toString());
            }
        }
        return Optional.empty();
    }

    private List<String> roles(BiscuitAuthenticationContext context) throws Error {
        List<String> roles = new ArrayList<>();
        Set<Fact> facts = context.getAuthorizer().query(configuration.getAuthentication().getRolesQuery(), BiscuitTokenValidator.runLimits(configuration));
        for (Fact fact : facts) {
            List<Term> terms = fact.terms();
            if (!terms.isEmpty()) {
                roles.add(BiscuitTermMapper.toJavaValue(terms.get(0)).toString());
            }
        }
        return roles;
    }
}
