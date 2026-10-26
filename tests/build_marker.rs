//! The update notice shows a different command per build kind, so the two scripts that make
//! release and Docker builds must tell the compiler which one they are.

fn read(file: &str) -> String {
    std::fs::read_to_string(format!("{}/{file}", env!("CARGO_MANIFEST_DIR")))
        .unwrap_or_else(|error| panic!("cannot read {file}: {error}"))
}

#[test]
fn the_release_script_marks_release_builds() {
    let script = read("scripts/build-release.sh");

    let marker = script
        .find("export PICOGUARD_BUILD=release")
        .expect("the release script exports the build marker");
    let first_build = script
        .find("cargo zigbuild")
        .expect("the release script builds with cargo zigbuild");

    assert!(marker < first_build);
}

#[test]
fn the_dockerfile_marks_docker_builds() {
    let dockerfile = read("Dockerfile");

    let first_stage = dockerfile
        .find("\nFROM ")
        .expect("the Dockerfile has a build stage");
    let last_stage = dockerfile
        .find("FROM scratch")
        .expect("the Dockerfile has a final stage");
    let marker = dockerfile
        .find("ENV PICOGUARD_BUILD=docker")
        .expect("the build stage sets the build marker");
    let build = dockerfile
        .find("RUN cargo build")
        .expect("the build stage runs cargo build");

    assert!(first_stage < marker && marker < build && build < last_stage);
}
