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
package io.micronaut.security.token

import io.micronaut.security.token.config.TokenConfiguration
import spock.lang.Specification
import spock.lang.Unroll

class DefaultRolesFinderSpec extends Specification {

    private static DefaultRolesFinder rolesFinder(String separator) {
        new DefaultRolesFinder(new TokenConfiguration() {
            @Override
            String getRolesSeparator() {
                separator
            }
        })
    }

    @Unroll
    void "roles value #value is split on the literal separator '#separator'"(String separator, String value, List<String> expected) {
        when:
        List<String> roles = rolesFinder(separator).resolveRoles([roles: value])

        then:
        noExceptionThrown()
        roles == expected

        where:
        separator | value           || expected
        '|'       | 'ADMIN|USER'    || ['ADMIN', 'USER']
        '.'       | 'a.b'           || ['a', 'b']
        '+'       | 'a+b'           || ['a', 'b']
        '('       | 'a(b'           || ['a', 'b']
        ','       | 'ADMIN, USER'   || ['ADMIN', 'USER']
        ','       | 'ADMIN,,USER'   || ['ADMIN', 'USER']
        ','       | ',ADMIN,USER,'  || ['ADMIN', 'USER']
        ' '       | 'read  write'   || ['read', 'write']
        ', '      | 'ADMIN, USER'   || ['ADMIN', 'USER']
        '\\s+'    | 'ADMIN\\s+USER' || ['ADMIN', 'USER']
        ','       | 'ADMIN'         || ['ADMIN']
    }

    void "a collection claim is not modified by the separator"() {
        when:
        List<String> roles = rolesFinder(',').resolveRoles([roles: ['ADMIN, USER', ' VIEWER']])

        then:
        roles == ['ADMIN, USER', ' VIEWER']
    }

    void "a string claim is not split when no separator is configured"() {
        expect:
        rolesFinder(null).resolveRoles([roles: 'ADMIN,USER']) == ['ADMIN,USER']
    }

    void "null attributes resolve to no roles"() {
        expect:
        rolesFinder(',').resolveRoles(null) == []
    }
}
