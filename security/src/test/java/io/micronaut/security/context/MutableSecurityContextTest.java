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
package io.micronaut.security.context;

import io.micronaut.http.HttpStatus;
import io.micronaut.security.authentication.Authentication;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

class MutableSecurityContextTest {

    @Test
    void startsEmpty() {
        MutableSecurityContext securityContext = new MutableSecurityContext();

        assertNull(securityContext.getAuthentication());
        assertNull(securityContext.getToken());
        assertNull(securityContext.getRejectionStatus());
    }

    @Test
    void withersStoreValuesAndReturnSameContext() {
        MutableSecurityContext securityContext = new MutableSecurityContext();
        Authentication authentication = Authentication.build("sherlock");

        assertSame(securityContext, securityContext.withAuthentication(authentication));
        assertSame(securityContext, securityContext.withToken("jwt-token"));
        assertSame(securityContext, securityContext.withRejectionStatus(HttpStatus.FORBIDDEN.getCode()));

        assertSame(authentication, securityContext.getAuthentication());
        assertEquals("jwt-token", securityContext.getToken());
        assertEquals(HttpStatus.FORBIDDEN.getCode(), securityContext.getRejectionStatus());
    }

    @Test
    void withersAcceptNullToClearValues() {
        MutableSecurityContext securityContext = new MutableSecurityContext();
        securityContext.withAuthentication(Authentication.build("sherlock"))
            .withToken("jwt-token")
            .withRejectionStatus(HttpStatus.UNAUTHORIZED.getCode());

        securityContext.withAuthentication(null)
            .withToken(null)
            .withRejectionStatus(null);

        assertNull(securityContext.getAuthentication());
        assertNull(securityContext.getToken());
        assertNull(securityContext.getRejectionStatus());
    }

    @Test
    void clearRemovesAllValues() {
        MutableSecurityContext securityContext = new MutableSecurityContext();
        securityContext.withAuthentication(Authentication.build("sherlock"))
            .withToken("jwt-token")
            .withRejectionStatus(HttpStatus.UNAUTHORIZED.getCode());

        securityContext.clear();

        assertNull(securityContext.getAuthentication());
        assertNull(securityContext.getToken());
        assertNull(securityContext.getRejectionStatus());
    }
}
