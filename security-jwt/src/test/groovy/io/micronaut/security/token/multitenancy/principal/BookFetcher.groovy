package io.micronaut.security.token.multitenancy.principal

interface BookFetcher {
    List<String> findAll()
}
