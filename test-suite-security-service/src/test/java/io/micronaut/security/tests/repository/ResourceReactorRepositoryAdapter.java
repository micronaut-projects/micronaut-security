package io.micronaut.security.tests.repository;

import io.micronaut.security.tests.entity.ResourceEntity;
import io.micronaut.security.utils.SecurityService;
import jakarta.inject.Singleton;
import reactor.core.publisher.Mono;

@Singleton
public class ResourceReactorRepositoryAdapter implements ResourceRepository {
    private final ResourceReactorCrudRepository resourceReactorCrudRepository;
    private final SecurityService securityService;

    public ResourceReactorRepositoryAdapter(ResourceReactorCrudRepository resourceReactorCrudRepository, SecurityService securityService) {
        this.resourceReactorCrudRepository = resourceReactorCrudRepository;
        this.securityService = securityService;
    }

    @Override
    public Mono<String> findByResourceId(String id) {
        return resourceReactorCrudRepository.findByResourceId(id).defaultIfEmpty(new ResourceEntity())
                .map(i -> securityService.username().orElse("nouser"));
    }
}
