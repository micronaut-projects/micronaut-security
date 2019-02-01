package io.micronaut.security.oauth2.openid.configuration

import io.micronaut.context.annotation.Requires
import io.micronaut.context.annotation.Value
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule

@Requires(property = 'openidconfigurationfile')
@Requires(property = 'spec.name', value='MockHttpServer')
@Secured(SecurityRule.IS_ANONYMOUS)
@Controller('${opendiconfigurationpath:/.well-known}')
class FileOpenIdConfigurationController {

    private final int called = 0
    private final String text

    FileOpenIdConfigurationController(@Value('${openidconfigurationfile}') String path) {
        File jsonFile = new File(path)
        assert jsonFile
        text = jsonFile.text
    }

    @Get("/openid-configuration")
    String index() {
        called++
        text
    }
}
