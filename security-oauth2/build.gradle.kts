plugins {
    id("io.micronaut.build.internal.security-module")
}

dependencies {
    annotationProcessor(mn.micronaut.graal)
    annotationProcessor(mnSerde.micronaut.serde.processor)
    annotationProcessor(projects.micronautSecurityProcessor)
    annotationProcessor(mnValidation.micronaut.validation.processor)

    api(mnValidation.validation) //  // jakarta.validation:jakarta.validation-api
    testImplementation(mnValidation.micronaut.validation)
    compileOnly(mn.micronaut.inject.java)
    compileOnly(projects.micronautSecurityJwt)
    compileOnly(mn.micronaut.http.server)
    api(projects.micronautSecurity)
    implementation(mn.micronaut.http.client.core)
    compileOnly(mn.jackson.databind)
    compileOnly(mnSession.micronaut.session)
    implementation(mnReactor.micronaut.reactor)

    testCompileOnly(projects.micronautSecurityProcessor)

    testImplementation(mnSerde.micronaut.serde.jackson)
    testImplementation(projects.micronautSecuritySession)
    testImplementation(mn.micronaut.http.client)
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(mnTestResources.testcontainers.core)
    testImplementation(mn.groovy.json)
    testImplementation(projects.micronautSecurityJwt)
    testImplementation(projects.testSuiteUtils)
    testImplementation(projects.testSuiteUtilsSecurity)
    testImplementation(projects.testSuiteKeycloak16)
    testImplementation(mnLogging.logback.classic)
    testImplementation(libs.system.stubs.core)
}
