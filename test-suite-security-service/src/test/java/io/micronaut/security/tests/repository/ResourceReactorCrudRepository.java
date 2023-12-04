package io.micronaut.security.tests.repository;

import io.micronaut.data.annotation.Repository;
import io.micronaut.data.repository.reactive.ReactorCrudRepository;
import io.micronaut.security.tests.entity.ResourceEntity;
import reactor.core.publisher.Mono;

@Repository
public interface ResourceReactorCrudRepository extends ReactorCrudRepository<ResourceEntity, Long> {
    Mono<ResourceEntity> findByResourceId(String resourceId);
}
