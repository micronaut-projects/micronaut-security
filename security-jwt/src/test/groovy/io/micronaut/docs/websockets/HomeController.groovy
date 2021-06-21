package io.micronaut.docs.websockets

import io.micronaut.context.annotation.Requires
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule

import io.micronaut.core.annotation.Nullable

@Requires(property = "spec.name", value = "websockets")
@Secured(SecurityRule.IS_ANONYMOUS)
@Controller
class HomeController {

    private final WebsocketsHtmlProvider websocketsHtmlProvider

    HomeController(WebsocketsHtmlProvider websocketsHtmlProvider) {
        this.websocketsHtmlProvider = websocketsHtmlProvider
    }

    @Produces(MediaType.TEXT_HTML)
    @Get
    String index(@Nullable String jwt) {
        websocketsHtmlProvider.html(jwt)

    }
}
