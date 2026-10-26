# Build picoguard from source into a static musl binary, then ship only that
# binary and a default config in an image with nothing else in it.
#
#   docker build -t picoguard .
#   docker run -d -p 53:53/udp -p 53:53/tcp -p 8080:8080 picoguard
#
# compose.yaml in this folder runs it with a read-only root file system and no
# capabilities.

FROM rust:1.99.1-alpine3.24 AS build

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

# The final image has no shell, so the state directory is made here.
RUN mkdir -p /out/var/lib/picoguard \
    && chown 65532:65532 /out/var/lib/picoguard \
    && chmod 0750 /out/var/lib/picoguard

FROM scratch

COPY --from=build /src/target/release/picoguard /usr/local/bin/picoguard
COPY --from=build --chown=65532:65532 /out/var/lib/picoguard /var/lib/picoguard
COPY dist/picoguard.docker.toml /etc/picoguard/picoguard.toml

# Port 53 for a non-root user relies on Docker's default of
# net.ipv4.ip_unprivileged_port_start=0 inside the container.
USER 65532:65532
EXPOSE 53/udp 53/tcp 8080/tcp
ENTRYPOINT ["/usr/local/bin/picoguard", "-c", "/etc/picoguard/picoguard.toml"]
