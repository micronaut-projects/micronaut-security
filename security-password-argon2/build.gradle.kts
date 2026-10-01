import io.micronaut.build.TestFramework
plugins {
    id("io.micronaut.build.internal.security-full-coverage")
}
dependencies {
    api(projects.micronautSecurityPassword)
    implementation(libs.managed.password4j)
    testAnnotationProcessor(mn.micronaut.inject.java)
    testImplementation(projects.micronautSecurityPasswordTck)
    testImplementation(mnTest.micronaut.test.junit5)
    testImplementation(mnTest.junit.jupiter.params)
    testImplementation(mnTest.junit.platform.suite)
    testRuntimeOnly(mnTest.junit.jupiter.engine)
    testRuntimeOnly(mnLogging.logback.classic)
}
tasks.withType<Test> {
    useJUnitPlatform()
}
micronautBuild {
    binaryCompatibility.enabledAfter("5.5.0")
    testFramework = TestFramework.JUNIT6
}
