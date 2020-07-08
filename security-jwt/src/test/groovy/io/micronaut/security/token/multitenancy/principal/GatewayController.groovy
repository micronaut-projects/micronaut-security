package io.micronaut.security.token.multitenancy.principal

import io.micronaut.context.annotation.Requires
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule

@Requires(property = 'spec.name', value = 'multitenancy.principal.gateway')
@Controller("/")
class GatewayController {

    private final BookFetcher bookFetcher

    GatewayController(BookFetcher bookFetcher) {
        this.bookFetcher = bookFetcher
    }

    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Get("/")
    List<String> index() {
        List<String> booksNames = bookFetcher.findAll()

        booksNames
    }
}
