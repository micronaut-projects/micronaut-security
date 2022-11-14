package io.micronaut.security.test.aot.authserver.a;

import io.micronaut.core.io.ResourceLoader;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;

@Controller("/us-east-1_4OqDoWVrZ/.well-known")
class OpenIdConfigurationController extends JsonController {
    OpenIdConfigurationController(ResourceLoader resourceLoader) {
        super(resourceLoader, "openidconfiguration.json");
    }


    @Get("/openid-configuration")
    String index() {
        return json;
    }
}
