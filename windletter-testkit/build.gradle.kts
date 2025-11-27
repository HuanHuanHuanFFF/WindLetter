val junitVersion: String by rootProject.extra
val jcsVersion: String by rootProject.extra

dependencies {
    implementation(project(":windletter-api"))
    implementation(project(":windletter-protocol"))
    implementation(project(":windletter-crypto"))
    implementation("io.github.erdtman:java-json-canonicalization:$jcsVersion")

    testImplementation(platform("org.junit:junit-bom:$junitVersion"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("io.github.erdtman:java-json-canonicalization:$jcsVersion")
}
