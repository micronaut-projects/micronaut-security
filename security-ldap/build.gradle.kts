plugins {
    id("io.micronaut.build.internal.security-module")
}

dependencies {
    annotationProcessor(mn.micronaut.graal)
    testAnnotationProcessor(mn.micronaut.inject.java)

    api(projects.micronautSecurity)

    implementation(mnReactor.micronaut.reactor)
    testImplementation(mn.reactor.test)

    testImplementation(mn.micronaut.http.client)
    testImplementation(mnSerde.micronaut.serde.jackson)
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(libs.unboundid.ldapsdk)
    testImplementation(libs.junit.jupiter.api)
    testRuntimeOnly(libs.junit.jupiter.engine)
}
