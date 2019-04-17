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
