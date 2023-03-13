plugins {
    id("io.micronaut.build.internal.security-module")
}

dependencies {
    annotationProcessor(mn.micronaut.graal)
    annotationProcessor(mnSerde.micronaut.serde.processor)
    implementation(mnSerde.micronaut.serde.jackson)
    api(mn.micronaut.http)
    api(mn.micronaut.http.server)
    annotationProcessor(mnValidation.micronaut.validation.processor)
    api(mnValidation.micronaut.validation)
    api(projects.micronautSecurityAnnotations)
    implementation(mn.reactor)
    compileOnly(mn.micronaut.management)
    compileOnly(mn.jackson.databind)
    testImplementation(mnReactor.micronaut.reactor)
    testImplementation(mn.micronaut.management)
    testImplementation(mn.micronaut.http.client)
    testAnnotationProcessor(projects.micronautSecurityAnnotations)
    testAnnotationProcessor(mn.micronaut.inject.java)
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(projects.testSuiteUtils)
    testImplementation(mn.snakeyaml)
    testImplementation(libs.bcpkix)
}
