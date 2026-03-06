FROM rust:1-bookworm AS build

WORKDIR /usr/src/authy

RUN apt-get update && apt-get install -y --no-install-recommends musl-tools ca-certificates libclang-dev libc-dev

RUN USER=root cargo init --bin /usr/src/authy
COPY Cargo.toml Cargo.lock .
RUN cargo build --release

# Copy the source and build the application.
COPY src src
RUN touch src/main.rs
RUN cargo build --locked --frozen --offline --release

# Copy the statically-linked binary into a scratch container.
FROM debian:bookworm-slim
COPY --from=build /usr/src/authy/target/release/authy .
USER 1000
ENTRYPOINT ["./authy"]

STOPSIGNAL SIGINT
