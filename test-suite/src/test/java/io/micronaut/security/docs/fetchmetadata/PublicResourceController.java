package io.micronaut.security.docs.fetchmetadata;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;

@Requires(property = "spec.name", value = "PublicResourceFetchMetadataRuleTest")
@Secured(SecurityRule.IS_ANONYMOUS)
@Controller
class PublicResourceController {

    @Get(uri = "/favicon.ico", produces = MediaType.TEXT_PLAIN)
    String favicon() {
        return "icon";
    }

    @Get(uri = "/account", produces = MediaType.TEXT_PLAIN)
    String account() {
        return "account";
    }
}
