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
package io.micronaut.security.oauth2.grants.password.passwordflow

import io.micronaut.context.annotation.Requires
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Body
import io.micronaut.http.annotation.Consumes
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Post
import io.micronaut.security.annotation.Secured
import io.micronaut.security.oauth2.grants.PasswordGrant
import io.micronaut.security.rules.SecurityRule

@Secured(SecurityRule.IS_ANONYMOUS)
@Requires(property = "spec.name", value="passwordFlowMockHttpServer")
@Controller("/oauth2")
class Oauth2Controller {

    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Post("/token")
    String token(@Body PasswordGrant passwordGrant) {
        '{"access_token":"MTQ0NjOkZmQ5OTM5NDE9ZTZjNGZmZjI3","token_type":"bearer","expires_in":3600,"scope":"create","id_token":"MTQ0NjOkZmQ5OTM5NDE9ZTZjNGZmZjI3"}'
    }
}
