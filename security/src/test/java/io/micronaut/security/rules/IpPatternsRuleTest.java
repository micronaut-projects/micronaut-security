/*
 * Copyright 2026 original authors
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

import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.simple.SimpleHttpRequest;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.token.DefaultRolesFinder;
import io.micronaut.security.token.config.TokenConfiguration;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import reactor.core.publisher.Mono;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class IpPatternsRuleTest {

    private static final List<String> DOCUMENTED_PATTERNS = Arrays.asList("127.0.0.1", "192.168.1.*");

    @ParameterizedTest
    @ValueSource(strings = {"127.0.0.1", "192.168.1.0", "192.168.1.5", "192.168.1.255"})
    void documentedPatternsAdmitAddressesInsideTheRange(String hostAddress) {
        assertEquals(SecurityRuleResult.UNKNOWN, check(DOCUMENTED_PATTERNS, hostAddress));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "192.168.10.5",
        "192.168.19.5",
        "192.168.100.5",
        "192.168.199.5",
        "192.168.2.5",
        "127.0.0.2",
        "127.0.0.10",
        "10.0.0.1"
    })
    void documentedPatternsRejectAddressesOutsideTheRange(String hostAddress) {
        assertEquals(SecurityRuleResult.REJECTED, check(DOCUMENTED_PATTERNS, hostAddress));
    }

    @ParameterizedTest
    @CsvSource({
        "192.168.*, 192.168.10.5, UNKNOWN",
        "192.168.*, 192.169.10.5, REJECTED",
        "10.*.0.1, 10.5.0.1, UNKNOWN",
        "10.*.0.1, 10.5.0.11, REJECTED",
        "0:0:0:0:0:0:0:1, 0:0:0:0:0:0:0:1, UNKNOWN",
        "0:0:0:0:0:0:0:1, 0:0:0:0:0:0:0:2, REJECTED",
        "fe80:*, fe80:0:0:0:0:0:0:1, UNKNOWN",
        "fe80:*, fe81:0:0:0:0:0:0:1, REJECTED",
        "FE80:*, fe80:0:0:0:0:0:0:1, UNKNOWN",
        "FE80:0:0:0:0:0:0:1, fe80:0:0:0:0:0:0:1, UNKNOWN",
        "FE80:*, fe81:0:0:0:0:0:0:1, REJECTED",
        "192.168.*.1, 192.168.2.1, UNKNOWN",
        "10.*.1, 10.9.8.1, REJECTED",
        "*:1, 0:0:0:0:0:0:0:1, REJECTED",
        "*, 10.9.8.1, UNKNOWN",
        "*, 0:0:0:0:0:0:0:1, UNKNOWN"
    })
    void wildcardPatternsTreatDotsAndColonsLiterally(String pattern, String hostAddress, SecurityRuleResult expected) {
        assertEquals(expected, check(Collections.singletonList(pattern), hostAddress));
    }

    @ParameterizedTest
    @CsvSource({
        "192\\.168\\.1\\.\\d+, 192.168.1.5, UNKNOWN",
        "192\\.168\\.1\\.\\d+, 192.168.10.5, REJECTED",
        "'10\\.0\\.(1|2)\\.[0-9]{1,3}', 10.0.2.100, UNKNOWN",
        "'10\\.0\\.(1|2)\\.[0-9]{1,3}', 10.0.3.100, REJECTED",
        "^172\\.16\\..*$, 172.16.40.2, UNKNOWN",
        "^172\\.16\\..*$, 172.17.40.2, REJECTED",
        "'192\\.168\\.1\\.\\d+|10\\.0\\.0\\.1', 192.168.1.5, UNKNOWN",
        "'192\\.168\\.1\\.\\d+|10\\.0\\.0\\.1', 10.0.0.1, UNKNOWN",
        "'192\\.168\\.1\\.\\d+|10\\.0\\.0\\.1', 192.168.10.5, REJECTED",
        "'192\\.168\\.1\\.\\d+|10\\.0\\.0\\.1', 10.0.0.11, REJECTED",
        "'.*', 192.168.10.5, UNKNOWN",
        "'.*', 0:0:0:0:0:0:0:1, UNKNOWN"
    })
    void regularExpressionPatternsKeepRegularExpressionSemantics(String pattern, String hostAddress, SecurityRuleResult expected) {
        assertEquals(expected, check(Collections.singletonList(pattern), hostAddress));
    }

    @ParameterizedTest
    @ValueSource(strings = {"127.0.0.1", "192.168.10.5", "0:0:0:0:0:0:0:1"})
    void anywhereAdmitsEveryAddress(String hostAddress) {
        assertEquals(SecurityRuleResult.UNKNOWN, check(Collections.singletonList("0.0.0.0"), hostAddress));
        assertEquals(SecurityRuleResult.UNKNOWN, check(Arrays.asList("10.0.0.1", "0.0.0.0"), hostAddress));
    }

    private static SecurityRuleResult check(List<String> patterns, String hostAddress) {
        SecurityConfigurationProperties securityConfiguration = new SecurityConfigurationProperties();
        securityConfiguration.setIpPatterns(patterns);
        IpPatternsRule rule = new IpPatternsRule(new DefaultRolesFinder(new TokenConfiguration() { }), securityConfiguration);
        HttpRequest<?> request = new SimpleHttpRequest<Object>(HttpMethod.GET, "/anonymous", null) {
            @Override
            public InetSocketAddress getRemoteAddress() {
                try {
                    return new InetSocketAddress(InetAddress.getByName(hostAddress), 12345);
                } catch (UnknownHostException e) {
                    throw new IllegalStateException(e);
                }
            }
        };
        return Mono.from(rule.check(request, null, null)).block();
    }
}
