plugins {
    id("java-library")
    id("io.micronaut.build.internal.security-tests")
}

dependencies {
    testImplementation(platform(mnTest.micronaut.test.bom))
    testImplementation(libs.junit.platform.engine)
    testImplementation(libs.junit.jupiter.engine)
    testImplementation(projects.testSuiteJwtTck)
}
tasks.withType<Test> {
    useJUnitPlatform()
}