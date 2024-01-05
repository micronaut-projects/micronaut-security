plugins {
    id("io.micronaut.build.internal.security-module")
}
dependencies {
    compileOnly("io.micronaut:micronaut-core-processor")
    compileOnly(mnData.micronaut.data.model)
}
