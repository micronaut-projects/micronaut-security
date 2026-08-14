import io.micronaut.build.TestFramework
plugins {
    id("io.micronaut.build.internal.security-module")
}
dependencies {
    implementation(mn.micronaut.http.client.core)
    testImplementation(mn.micronaut.http.client)
    testAnnotationProcessor(mn.micronaut.inject.java)
    testRuntimeOnly(mnLogging.logback.classic)
}
micronautBuild {
    binaryCompatibility.enabledAfter("5.4.0")
    testFramework = TestFramework.JUNIT6
}
