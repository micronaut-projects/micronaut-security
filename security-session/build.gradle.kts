plugins {
    id("io.micronaut.build.internal.security-module")
}

dependencies {
    annotationProcessor(mn.micronaut.graal)
    api(mnSession.micronaut.session)
    api(mn.micronaut.router)
    api(projects.micronautSecurity)
    implementation(mnReactor.micronaut.reactor)

    testAnnotationProcessor(mnSerde.micronaut.serde.processor)
    testImplementation(mnSerde.micronaut.serde.jackson)
    testImplementation(platform(mnTest.boms.testcontainers))
    testImplementation(libs.testcontainers)
    testImplementation(mn.micronaut.http.client)
    testImplementation(mn.micronaut.inject.groovy)
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(mnTest.micronaut.test.junit5)
    testRuntimeOnly(mnTest.junit.jupiter.engine)
    testImplementation(projects.testSuiteUtils)
    testImplementation(projects.testSuiteUtilsSecurity)
}
