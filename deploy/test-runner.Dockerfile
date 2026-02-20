FROM rust:1.93.1-bullseye

RUN rustup component add llvm-tools-preview \
    && cargo install cargo-llvm-cov --version 0.8.4 --locked

WORKDIR /app
