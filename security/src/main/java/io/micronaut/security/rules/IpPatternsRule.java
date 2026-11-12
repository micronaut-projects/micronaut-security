/*
 * Copyright 2017-2023 original authors
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

import io.micronaut.context.annotation.Requires;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.config.SecurityConfiguration;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.token.RolesFinder;
import jakarta.inject.Singleton;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.regex.Pattern;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import static io.micronaut.security.utils.LoggingUtils.debug;

/**
 * A security rule implementation backed by the {@link SecurityConfigurationProperties#getIpPatterns()} ()}.
 *
 * <p>Each configured pattern is interpreted in one of two ways:</p>
 * <ul>
 *     <li>A pattern made only of hexadecimal digits, dots, colons and {@code *} (for example {@code 127.0.0.1},
 *     {@code 192.168.1.*} or {@code fe80:*}) is an IP wildcard: dots and colons match literally, a {@code *}
 *     inside the pattern matches within one address segment and a trailing {@code *} matches the rest of the
 *     address. {@code 192.168.1.*} therefore matches {@code 192.168.1.0} to {@code 192.168.1.255} only, and not
 *     {@code 192.168.10.5}; {@code 192.168.*.1} matches {@code 192.168.2.1} but not {@code 192.168.2.3.1}.
 *     Hexadecimal digits match regardless of case.</li>
 *     <li>Any other pattern (for example {@code 192\.168\.1\.\d+}), including one starting with a dot such as
 *     {@code .*}, is compiled as a regular expression and must match the whole host address.</li>
 * </ul>
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@Requires(classes = HttpRequest.class)
@Singleton
public class IpPatternsRule extends AbstractSecurityRule<HttpRequest<?>> {

    /**
     * The order of the rule.
     */
    public static final Integer ORDER = SecuredAnnotationRule.ORDER - 100;

    private static final Logger LOG = LoggerFactory.getLogger(IpPatternsRule.class);

    /**
     * Patterns made only of these characters are IP wildcards rather than regular expressions.
     */
    private static final Pattern IP_WILDCARD = Pattern.compile("[0-9A-Fa-f.:*]+");

    private static final String WILDCARD = "*";

    private final List<String> ipPatterns;
    private final List<Pattern> patternList;
    private final boolean anywhere;

    /**
     * @param rolesFinder Roles Parser
     * @param securityConfiguration Security Configuration
     */
    public IpPatternsRule(RolesFinder rolesFinder,
                          SecurityConfiguration securityConfiguration) {
        super(rolesFinder);
        this.ipPatterns = List.copyOf(securityConfiguration.getIpPatterns());
        this.anywhere = ipPatterns.contains(SecurityConfigurationProperties.ANYWHERE);
        this.patternList = ipPatterns.stream()
                .map(IpPatternsRule::compile)
                .toList();
    }

    /**
     * Compiles a configured IP pattern. IP wildcards (digits, dots, colons and {@code *}, not starting with a dot) are
     * quoted so that dots and colons match literally. A {@code *} inside the wildcard matches within one address
     * segment, a trailing {@code *} matches the rest of the address and hexadecimal digits match regardless of case.
     * Every other pattern, including an "allow all" regular expression such as {@code .*}, is compiled as a regular
     * expression.
     *
     * @param ipPattern The configured IP pattern
     * @return The compiled pattern
     */
    @NonNull
    private static Pattern compile(@NonNull String ipPattern) {
        if (IP_WILDCARD.matcher(ipPattern).matches() && !ipPattern.startsWith(".")) {
            String[] parts = ipPattern.split(Pattern.quote(WILDCARD), -1);
            StringBuilder regex = new StringBuilder();
            for (int i = 0; i < parts.length; i++) {
                if (!parts[i].isEmpty()) {
                    regex.append(Pattern.quote(parts[i]));
                }
                if (i < parts.length - 1) {
                    regex.append(i == parts.length - 2 && parts[i + 1].isEmpty() ? ".*" : "[^.:]*");
                }
            }
            return Pattern.compile(regex.toString(), Pattern.CASE_INSENSITIVE);
        }
        return Pattern.compile(ipPattern);
    }

    @Override
    public int getOrder() {
        return ORDER;
    }

    @Override
    public Publisher<SecurityRuleResult> check(HttpRequest<?> request, @Nullable Authentication authentication) {

        if (patternList.isEmpty()) {
            debug(LOG, "No IP patterns provided. Skipping host address check.");
            return Mono.just(SecurityRuleResult.UNKNOWN);
        } else {
            try {
                InetSocketAddress socketAddress = request.getRemoteAddress();
                //noinspection ConstantConditions https://github.com/micronaut-projects/micronaut-security/issues/186
                if (socketAddress == null) {
                    debug(LOG, "Request remote address was not found. Continuing request processing.");
                    return Mono.just(SecurityRuleResult.UNKNOWN);
                }
                if (socketAddress.getAddress() == null) {
                    debug(LOG, "Could not resolve the InetAddress. Continuing request processing.");
                    return Mono.just(SecurityRuleResult.UNKNOWN);
                }
                String hostAddress = socketAddress.getAddress().getHostAddress();
                if (anywhere || patternList.stream().anyMatch(pattern -> pattern.matcher(hostAddress).matches())) {
                    debug(LOG, "One or more of the IP patterns matched the host address [{}]. Continuing request processing.", hostAddress);
                    return Mono.just(SecurityRuleResult.UNKNOWN);
                } else {
                    debug(LOG, "None of the IP patterns [{}] matched the host address [{}]. Rejecting the request.", ipPatterns, hostAddress);
                    return Mono.just(SecurityRuleResult.REJECTED);
                }
            } catch (IllegalArgumentException e) {
                debug(LOG, "IllegalArgumentException thrown while getting the request remote address. Continuing request processing.");
                return Mono.just(SecurityRuleResult.UNKNOWN);
            }
        }
    }
}
