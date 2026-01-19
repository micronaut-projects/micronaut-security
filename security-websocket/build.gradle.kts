plugins {
    id("io.micronaut.build.internal.security-module")
}

dependencies {
    api(projects.micronautSecurity)

    implementation(mn.micronaut.websocket)

    annotationProcessor(mnSerde.micronaut.serde.processor)
    annotationProcessor(projects.micronautSecurityProcessor)
    annotationProcessor(mnValidation.micronaut.validation.processor)
}
