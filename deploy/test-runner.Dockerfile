FROM rust:1.93-bullseye

RUN rustup component add llvm-tools-preview \
    && cargo install cargo-llvm-cov --locked

WORKDIR /app
