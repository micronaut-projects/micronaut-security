plugins {
    id("io.micronaut.build.internal.security-module")
}
dependencies {
    api(mn.micronaut.aop)
    compileOnly("io.micronaut:micronaut-core-processor")
    compileOnly(mnData.micronaut.data.model)
}
