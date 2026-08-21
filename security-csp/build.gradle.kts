import io.micronaut.build.TestFramework

plugins {
    id("io.micronaut.build.internal.security-module")
}
dependencies {
    annotationProcessor(mnSerde.micronaut.serde.processor)
    annotationProcessor(mnValidation.micronaut.validation.processor)
    api(projects.micronautSecurityReporting)
    api(mn.micronaut.http)
    compileOnly(mn.micronaut.http.server)
    api(mnSerde.micronaut.serde.api) {
        exclude(group = "io.micronaut", module = "micronaut-json-core")
    }
    api(mnValidation.validation)
    implementation(mn.micronaut.json.core)
    compileOnly(mnViews.micronaut.views.core)
    compileOnly(mnValidation.micronaut.validation)
    compileOnly(mn.jackson.databind)
    testAnnotationProcessor(mn.micronaut.inject.java)
    testImplementation(mnTest.micronaut.test.junit5)
    testRuntimeOnly(mnTest.junit.jupiter.engine)
    testRuntimeOnly(mnLogging.logback.classic)
    testImplementation(mn.micronaut.http.client)
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(mnValidation.micronaut.validation)
    testAnnotationProcessor(mnSerde.micronaut.serde.processor)
    testImplementation(mnSerde.micronaut.serde.jackson)
    testImplementation(mnViews.micronaut.views.thymeleaf)
}
tasks.withType<Test> {
    useJUnitPlatform()
}
micronautBuild {
    binaryCompatibility.enabledAfter("5.5.0")
    testFramework = TestFramework.JUNIT6
}
