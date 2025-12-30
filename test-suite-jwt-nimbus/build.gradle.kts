plugins {
    id("java-library")
    id("io.micronaut.build.internal.security-tests")
}

dependencies {
    testImplementation(platform(mnTest.micronaut.test.bom))
    testImplementation(mnTest.junit.platform.suite)
    testImplementation(mnTest.junit.jupiter.engine)
    testImplementation(projects.testSuiteJwtTck)
}
tasks.withType<Test> {
    useJUnitPlatform()
}
