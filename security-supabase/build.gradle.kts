plugins {
    id("io.micronaut.build.internal.security-module")
}
dependencies {
    annotationProcessor(mnSerde.micronaut.serde.processor)
    api(mnSerde.micronaut.serde.api)
    compileOnly(mn.micronaut.http.client.core)
    compileOnly(mn.jackson.databind)
    testImplementation(mnSerde.micronaut.serde.jackson)
    api(projects.micronautSecurity)
    testImplementation(mn.micronaut.http.client)
    testImplementation(platform(mnTest.boms.testcontainers))
    testImplementation(libs.testcontainers)
    testImplementation(libs.testcontainers.junit.jupiter)
}
micronautBuild {
    binaryCompatibility.enabledAfter("5.6.0")
}

