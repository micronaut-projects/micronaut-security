import io.micronaut.build.TestFramework

plugins {
    id("io.micronaut.build.internal.security-module")
}
dependencies {
    annotationProcessor(mnSerde.micronaut.serde.processor)
    annotationProcessor(mnValidation.micronaut.validation.processor)

    api(projects.micronautSecurityScimCore)
    api(mn.micronaut.http.server)
    api(mnValidation.validation)
    implementation(mnReactor.micronaut.reactor)

    compileOnly(mnValidation.micronaut.validation)

    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(mn.micronaut.http.client)
    testAnnotationProcessor(mn.micronaut.inject.java)
    testAnnotationProcessor(mnSerde.micronaut.serde.processor)
    testImplementation(mnSerde.micronaut.serde.jackson)
    testImplementation(mnValidation.micronaut.validation)
    testRuntimeOnly(mnLogging.logback.classic)
}
micronautBuild {
    binaryCompatibility.enabledAfter("5.4.0")
    testFramework = TestFramework.JUNIT6
}
