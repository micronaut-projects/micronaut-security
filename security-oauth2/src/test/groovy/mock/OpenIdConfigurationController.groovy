package mock

import io.micronaut.context.annotation.Requires
import io.micronaut.context.annotation.Value
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule

@Requires(property="spec.name", value="mockopenidprovider")
@Controller("/.well-known")
class OpenIdConfigurationController {

    String serverUrl

    OpenIdConfigurationController(@Value('${mockserver.url}') String mockserverUrl) {
        this.serverUrl = mockserverUrl
    }

    @Secured(SecurityRule.IS_ANONYMOUS)
    @Get("/openid-configuration")
    String index() {
        "{\"authorization_endpoint\":\"${serverUrl}/oauth2/authorize\",\"id_token_signing_alg_values_supported\":[\"RS256\"],\"issuer\":\"https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_ZLiEFD4b6\",\"jwks_uri\":\"https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_ZLiEFD4b6/.well-known/jwks.json\",\"response_types_supported\":[\"code\",\"token\",\"token id_token\"],\"scopes_supported\":[\"openid\",\"email\",\"phone\",\"profile\"],\"subject_types_supported\":[\"public\"],\"token_endpoint\":\"${serverUrl}/oauth2/token\",\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\"],\"userinfo_endpoint\":\"${serverUrl}/oauth2/userInfo\"}".toString()
    }
}
