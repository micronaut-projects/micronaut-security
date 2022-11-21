plugins {
    id("io.micronaut.build.internal.security-module")
}
dependencies {
    annotationProcessor(mn.micronaut.graal)
    annotationProcessor(mn.micronaut.serde.processor)
    implementation(mn.micronaut.serde.jackson)
    api(mn.micronaut.http)
    api(mn.micronaut.http.server)
    api(mn.micronaut.validation)
    api(project(":security-annotations"))
    implementation(libs.reactor.core)
    compileOnly(mn.micronaut.management)
    compileOnly(mn.jackson.databind)
    testImplementation(mn.micronaut.reactor)
    testImplementation(mn.micronaut.management)
    testImplementation(mn.micronaut.http.client)
    testAnnotationProcessor(project(":security-annotations"))
    testAnnotationProcessor(mn.micronaut.inject.java)
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(project(":test-suite-utils"))
    testImplementation(mn.snakeyaml)
}
