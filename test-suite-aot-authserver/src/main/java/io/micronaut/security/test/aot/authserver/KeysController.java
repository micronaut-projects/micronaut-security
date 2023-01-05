package io.micronaut.security.test.aot.authserver;

import io.micronaut.core.io.ResourceLoader;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;

@Controller
class KeysController extends JsonController {
    KeysController(ResourceLoader resourceLoader) {
        super(resourceLoader, "jwks.json");
    }

    @Get("/keys")
    String index() {
        return json;
    }
}
