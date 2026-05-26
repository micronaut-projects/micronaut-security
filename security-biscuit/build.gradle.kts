plugins {
    id("io.micronaut.build.internal.security-module")
}

dependencies {
    api(projects.micronautSecurity)
    api(libs.managed.biscuit)

    compileOnly(mn.micronaut.http.server)

    testAnnotationProcessor(mn.micronaut.inject.java)
    testImplementation(projects.micronautSecurityJwt)
    testImplementation(mnTest.micronaut.test.junit5)
    testImplementation(mn.micronaut.http.client)
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(mnReactor.micronaut.reactor)
    testImplementation(mnSerde.micronaut.serde.jackson)
    testRuntimeOnly(mnLogging.logback.classic)
    testRuntimeOnly(mnTest.junit.jupiter.engine)
}

tasks.withType<Test> {
    useJUnitPlatform()
}

micronautBuild {
    binaryCompatibility {
        enabledAfter("5.1.0")
    }
}
