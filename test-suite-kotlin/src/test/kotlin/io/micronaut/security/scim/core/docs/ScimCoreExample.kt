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
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

internal class ScimCoreExample {

    @Test
    fun createsUser() {
        //tag::user[]
        val user = User().apply {
            userName = "bjensen@example.com"
            name = Name(
                "Barbara Jensen", "Jensen", "Barbara", null, null, null
            )
            emails = listOf(MultiValuedAttribute(
                "bjensen@example.com", "work", true, null, null
            ))
            active = true
        }
        //end::user[]

        assertEquals(listOf(SchemaUris.USER), user.schemas)
        assertEquals("Jensen", requireNotNull(user.name).familyName())
    }

    @Test
    fun addsEnterpriseUserExtension() {
        val user = User()

        //tag::enterpriseUser[]
        user.enterpriseUser = EnterpriseUser(
            "701984", "4130", "Acme", "Platform", "Engineering", null
        )
        //end::enterpriseUser[]

        assertTrue(user.schemas.contains(SchemaUris.ENTERPRISE_USER))
    }

    @Test
    fun addsCustomExtension() {
        val user = User()

        //tag::customExtension[]
        val extensionSchema =
            "urn:example:params:scim:schemas:extension:custom:2.0:User"
        user.setExtension(extensionSchema, mapOf("badgeNumber" to "A-123"))
        //end::customExtension[]

        assertTrue(user.schemas.contains(extensionSchema))
        assertEquals(mapOf("badgeNumber" to "A-123"), user.getExtension(extensionSchema))
    }
}
