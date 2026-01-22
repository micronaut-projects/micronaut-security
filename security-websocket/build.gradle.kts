plugins {
    id("io.micronaut.build.internal.security-module")
}

dependencies {
    api(projects.micronautSecurity)

    implementation(mn.micronaut.websocket)

    annotationProcessor(mnSerde.micronaut.serde.processor)
    annotationProcessor(projects.micronautSecurityProcessor)
    annotationProcessor(mnValidation.micronaut.validation.processor)

    testImplementation(projects.micronautSecurityJwt)
    testImplementation(mn.micronaut.http.client)
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(mn.micronaut.websocket)
    testImplementation(mnSerde.micronaut.serde.jackson)
    testImplementation(mnReactor.micronaut.reactor)
}
