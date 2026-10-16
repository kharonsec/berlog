# syntax=docker/dockerfile:1

# ---- build: static musl binary -------------------------------------------
FROM rust:1.97-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src

# Cache dependencies separately from the source.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && touch src/lib.rs \
    && cargo build --release --locked \
    && rm -rf src

COPY src ./src
RUN touch src/main.rs src/lib.rs && cargo build --release --locked

# Directories the runtime image needs, owned by distroless "nonroot" (65532).
RUN mkdir -p /rootfs/var/log/berlog /rootfs/etc/berlog

# ---- runtime: distroless, no shell, non-root ----------------------------
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /src/target/release/berlog /usr/local/bin/berlog
COPY --from=build --chown=65532:65532 /rootfs/var/log/berlog /var/log/berlog
COPY docker/berlog.toml /etc/berlog/berlog.toml

USER 65532:65532
VOLUME ["/var/log/berlog"]

# 514 is the conventional syslog port; publish it onto the container's
# unprivileged 5514 (docker run -p 514:5514/udp -p 514:5514/tcp). Listening
# on 514 inside the container also works under Docker's default
# net.ipv4.ip_unprivileged_port_start=0 if you change the config.
EXPOSE 514/udp 514/tcp 5514/udp 5514/tcp

ENTRYPOINT ["/usr/local/bin/berlog"]
CMD ["-c", "/etc/berlog/berlog.toml"]
