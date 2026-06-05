plugins {
    id("io.micronaut.build.internal.security-module")
}

dependencies {
    annotationProcessor(mn.micronaut.graal)

    api(projects.micronautSecurity)

    implementation(mnReactor.micronaut.reactor)
    testImplementation(mn.reactor.test)

    testImplementation(mn.micronaut.http.client)
    testImplementation(mnSerde.micronaut.serde.jackson)
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(mnTest.micronaut.test.junit5)
    testRuntimeOnly(mnTest.junit.jupiter.engine)
    testImplementation(projects.testSuiteUtils)
    testImplementation(libs.unboundid.ldapsdk)
}
