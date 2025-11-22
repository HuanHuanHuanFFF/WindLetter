val jcsVersion: String by rootProject.extra
val junitVersion: String by rootProject.extra

dependencies {
    api(project(":windletter-core"))
    implementation(project(":windletter-crypto"))

    implementation("io.github.erdtman:java-json-canonicalization:$jcsVersion")
    testImplementation("io.github.erdtman:java-json-canonicalization:$jcsVersion")

    testImplementation(platform("org.junit:junit-bom:$junitVersion"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}
