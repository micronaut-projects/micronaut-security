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

import io.micronaut.http.HttpRequest;
import io.micronaut.security.config.SecurityConfiguration;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.token.RolesFinder;
import io.micronaut.security.token.config.TokenConfiguration;
import io.micronaut.web.router.RouteMatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.inject.Singleton;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * A security rule implementation backed by the {@link SecurityConfigurationProperties#getIpPatterns()} ()}.
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@Singleton
public class IpPatternsRule extends AbstractSecurityRule {

    /**
     * The order of the rule.
     */
    public static final Integer ORDER = SecuredAnnotationRule.ORDER - 100;

    private static final Logger LOG = LoggerFactory.getLogger(InterceptUrlMapRule.class);

    private final List<Pattern> patternList;

    /**
     * @deprecated use {@link #IpPatternsRule(RolesFinder, SecurityConfiguration)} instead.
     * @param tokenConfiguration Token Configuration
     * @param securityConfiguration Security Configuration
     */
    @Deprecated
    public IpPatternsRule(TokenConfiguration tokenConfiguration,
                          SecurityConfiguration securityConfiguration) {
        super(tokenConfiguration);
        this.patternList = securityConfiguration.getIpPatterns()
                        .stream()
                        .map(Pattern::compile)
                        .collect(Collectors.toList());
    }

    /**
     *
     * @param rolesFinder Roles Parser
     * @param securityConfiguration Security Configuration
     */
    @Inject
    public IpPatternsRule(RolesFinder rolesFinder,
                          SecurityConfiguration securityConfiguration) {
        super(rolesFinder);
        this.patternList = securityConfiguration.getIpPatterns()
                .stream()
                .map(Pattern::compile)
                .collect(Collectors.toList());
    }

    @Override
    public int getOrder() {
        return ORDER;
    }

    @Override
    public SecurityRuleResult check(HttpRequest request, @Nullable RouteMatch routeMatch, @Nullable Map<String, Object> claims) {

        if (patternList.isEmpty()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No IP patterns provided. Skipping host address check.");
            }
            return SecurityRuleResult.UNKNOWN;
        } else {
            InetSocketAddress socketAddress = request.getRemoteAddress();
            //noinspection ConstantConditions https://github.com/micronaut-projects/micronaut-security/issues/186
            if (socketAddress != null) {
                if (socketAddress.getAddress() != null) {
                    String hostAddress = socketAddress.getAddress().getHostAddress();

                    if (patternList.stream().anyMatch(pattern ->
                            pattern.pattern().equals(SecurityConfigurationProperties.ANYWHERE) ||
                                    pattern.matcher(hostAddress).matches())) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("One or more of the IP patterns matched the host address [{}]. Continuing request processing.", hostAddress);
                        }
                        return SecurityRuleResult.UNKNOWN;
                    } else {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("None of the IP patterns [{}] matched the host address [{}]. Rejecting the request.", patternList.stream().map(Pattern::pattern).collect(Collectors.toList()), hostAddress);
                        }
                        return SecurityRuleResult.REJECTED;
                    }
                } else {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Could not resolve the InetAddress. Continuing request processing.");
                    }
                    return SecurityRuleResult.UNKNOWN;
                }
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Request remote address was not found. Continuing request processing.");
                }
                return SecurityRuleResult.UNKNOWN;
            }
        }
    }
}
