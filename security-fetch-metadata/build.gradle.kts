import io.micronaut.build.TestFramework

plugins {
    id("io.micronaut.build.internal.security-module")
}
dependencies {
    api(mn.micronaut.http)
    compileOnly(mn.micronaut.http.server)
    testAnnotationProcessor(mn.micronaut.inject.java)
    testImplementation(mnTest.micronaut.test.junit5)
    testImplementation(mn.micronaut.http.client)
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(mnSerde.micronaut.serde.jackson)
    testRuntimeOnly(mnTest.junit.jupiter.engine)
    testRuntimeOnly(mnLogging.logback.classic)
}
tasks.withType<Test> {
    useJUnitPlatform()
}
micronautBuild {
    binaryCompatibility.enabledAfter("5.4.0")
    testFramework = TestFramework.JUNIT6
}
