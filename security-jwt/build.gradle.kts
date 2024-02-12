import org.gradle.api.tasks.testing.logging.TestExceptionFormat

plugins {
    id("io.micronaut.build.internal.security-module")
}

dependencies {
    annotationProcessor(mn.micronaut.graal)
    annotationProcessor(mnSerde.micronaut.serde.processor)
    annotationProcessor(mnValidation.micronaut.validation.processor)
    api(mnValidation.validation)
    testImplementation(mnValidation.micronaut.validation)
    api(projects.micronautSecurity)
    api(libs.managed.nimbus.jose.jwt)
    implementation(mnReactor.micronaut.reactor)
    testImplementation(libs.bcpkix.jdk15on)
    testImplementation(libs.bcprov.jdk15on)

    compileOnly(mn.micronaut.http.client.core)
    compileOnly(mn.micronaut.http.server)
    compileOnly(mn.micronaut.json.core)

    testImplementation(mn.micronaut.management)
    testImplementation(mn.micronaut.http.client)
    testAnnotationProcessor(mn.micronaut.inject.java)
    testImplementation(mnSerde.micronaut.serde.jackson)
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(projects.testSuiteUtils)
    testImplementation(projects.testSuiteUtilsSecurity)
    testImplementation(mnMultitenancy.micronaut.multitenancy)
    testImplementation(mnViews.micronaut.views.velocity)
    testRuntimeOnly(mnViews.velocity.engine.core)
    testRuntimeOnly(mnLogging.logback.classic)

    testImplementation(mn.snakeyaml)
    testImplementation(mn.micronaut.websocket)
    testImplementation(mn.groovy.json)
    testImplementation(mnTestResources.testcontainers.core)

    testImplementation(libs.system.stubs.core)
}

tasks.test {
    testLogging.showStandardStreams = true
    testLogging.exceptionFormat = TestExceptionFormat.FULL
}
