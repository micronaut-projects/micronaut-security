plugins {
    id("io.micronaut.build.internal.security-module")
}

dependencies {
    annotationProcessor(mn.micronaut.graal)
    annotationProcessor(mnSerde.micronaut.serde.processor)
    api(mnValidation.micronaut.validation.processor)
    implementation(mnSerde.micronaut.serde.jackson)
    api(mn.micronaut.http)
    api(mn.micronaut.http.server)
    api(mnValidation.micronaut.validation)
    api(projects.securityAnnotations)
    implementation(libs.reactor.core)
    compileOnly(mn.micronaut.management)
    compileOnly(mn.jackson.databind)
    testImplementation(mnReactor.micronaut.reactor)
    testImplementation(mn.micronaut.management)
    testImplementation(mn.micronaut.http.client)
    testAnnotationProcessor(projects.securityAnnotations)
    testAnnotationProcessor(mn.micronaut.inject.java)
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(projects.testSuiteUtils)
    testImplementation(mn.snakeyaml)
    testImplementation(libs.bcpkix)
}
