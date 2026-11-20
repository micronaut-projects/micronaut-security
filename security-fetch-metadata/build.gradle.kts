import io.micronaut.build.TestFramework

plugins {
    id("io.micronaut.build.internal.security-module")
}
dependencies {
    api(mn.micronaut.http)
    compileOnly(mn.micronaut.http.server)
    testImplementation(mn.micronaut.http.client)
    testImplementation(mn.micronaut.http.server.netty)
    testImplementation(mnSerde.micronaut.serde.jackson)
}
micronautBuild {
    binaryCompatibility.enabledAfter("5.6.0")
    testFramework = TestFramework.JUNIT6
}
