ARG RUST_VERSION=1.77
ARG DEBIAN_VERSION=bookworm
FROM --platform=${BUILDPLATFORM:-linux/amd64} rust:${RUST_VERSION}-slim-${DEBIAN_VERSION} AS builder
ARG BUILD_DEPS="binutils libssl-dev pkg-config git build-essential"
ARG FEATURES=""
# hadolint ignore=DL3027,DL3008,DL3015
RUN DEBIAN_FRONTEND=noninteractive apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get -y install ${BUILD_DEPS}
WORKDIR /usr/src/operator
COPY Cargo.lock Cargo.toml dummy.rs ./
RUN touch lib.rs && sed -i 's#src/lib.rs#lib.rs#' Cargo.toml \
 && CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build $FEATURES --release --bin dummy \
 && sed -i 's#lib.rs#src/lib.rs#' Cargo.toml
COPY . .
RUN CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build $FEATURES --release --bin kacp \
 && strip target/release/kacp

FROM --platform=${BUILDPLATFORM:-linux/amd64} debian:${DEBIAN_VERSION}-slim AS target
# hadolint ignore=DL3027,DL3008
COPY --from=builder /usr/src/operator/target/release/kacp /usr/local/bin/kacp
USER nobody
ENTRYPOINT ["kacp"]
