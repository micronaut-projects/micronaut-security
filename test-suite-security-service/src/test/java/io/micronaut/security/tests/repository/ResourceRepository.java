package io.micronaut.security.tests.repository;

import reactor.core.publisher.Mono;

public interface ResourceRepository {
    Mono<String> findByResourceId(String id);
}
