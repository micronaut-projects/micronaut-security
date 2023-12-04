package io.micronaut.security.tests.controllers;

import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.tests.repository.ResourceRepository;
import reactor.core.publisher.Mono;

@Controller("/foo")
class FooController {

    private final ResourceRepository repository;

    FooController(ResourceRepository repository) {
        this.repository = repository;
    }

    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Produces(MediaType.TEXT_PLAIN)
    @Get("/mono")
    Mono<String> mono() {
        return repository.findByResourceId("xxx");
    }
}
