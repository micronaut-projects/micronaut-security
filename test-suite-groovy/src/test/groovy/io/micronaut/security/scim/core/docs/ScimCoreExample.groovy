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
package io.micronaut.security.scim.core.docs

import io.micronaut.security.scim.core.EnterpriseUser
import io.micronaut.security.scim.core.MultiValuedAttribute
import io.micronaut.security.scim.core.Name
import io.micronaut.security.scim.core.SchemaUris
import io.micronaut.security.scim.core.User
import spock.lang.Specification

class ScimCoreExample extends Specification {

    void 'creates a user'() {
        when:
        //tag::user[]
        User user = new User()
        user.userName = 'bjensen@example.com'
        user.name = new Name(
                'Barbara Jensen', 'Jensen', 'Barbara', null, null, null)
        user.emails = [new MultiValuedAttribute(
                'bjensen@example.com', 'work', true, null, null)]
        user.active = true
        //end::user[]

        then:
        user.schemas == [SchemaUris.USER]
        user.name.familyName() == 'Jensen'
    }

    void 'adds the enterprise User extension'() {
        given:
        User user = new User()

        when:
        //tag::enterpriseUser[]
        user.enterpriseUser = new EnterpriseUser(
                '701984', '4130', 'Acme', 'Platform', 'Engineering', null)
        //end::enterpriseUser[]

        then:
        user.schemas.contains(SchemaUris.ENTERPRISE_USER)
    }

    void 'adds a custom extension'() {
        given:
        User user = new User()

        when:
        //tag::customExtension[]
        String extensionSchema =
                'urn:example:params:scim:schemas:extension:custom:2.0:User'
        user.setExtension(extensionSchema, [badgeNumber: 'A-123'])
        //end::customExtension[]

        then:
        user.schemas.contains(extensionSchema)
        user.getExtension(extensionSchema) == [badgeNumber: 'A-123']
    }
}
