# syntax=docker/dockerfile:1

ARG VERSION
ARG REPOSITORY

FROM --platform=$BUILDPLATFORM alpine:3.22 AS fetch
ARG VERSION
ARG REPOSITORY
ARG TARGETARCH
ARG TARGETVARIANT
RUN apk add --no-cache xz
WORKDIR /work
RUN set -eu; \
    test -n "${VERSION}" || { echo "pass --build-arg VERSION=x.y.z" >&2; exit 1; }; \
    test -n "${REPOSITORY}" || { echo "pass --build-arg REPOSITORY=owner/repo" >&2; exit 1; }; \
    case "${TARGETARCH}${TARGETVARIANT}" in \
      amd64) triple=x86_64-unknown-linux-musl ;; \
      arm64) triple=aarch64-unknown-linux-musl ;; \
      armv7) triple=armv7-unknown-linux-musleabihf ;; \
      *) echo "unsupported platform: ${TARGETARCH}${TARGETVARIANT}" >&2; exit 1 ;; \
    esac; \
    archive="mercurio-cli-${triple}.tar.xz"; \
    base="https://github.com/${REPOSITORY}/releases/download/v${VERSION#v}"; \
    wget -q "${base}/${archive}" "${base}/${archive}.sha256"; \
    echo "$(cut -d ' ' -f 1 "${archive}.sha256")  ${archive}" | sha256sum -c -; \
    mkdir out; tar -xJf "${archive}" -C out; \
    bin="$(find out -type f -name mercurio | head -n 1)"; \
    test -n "${bin}"; \
    install -m 0755 "${bin}" /mercurio

FROM scratch
ARG VERSION
LABEL org.opencontainers.image.title="mercurio" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=fetch /mercurio /mercurio
USER 65532:65532
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 CMD ["/mercurio", "serve", "--healthcheck", "--bind", "0.0.0.0:8000"]
ENTRYPOINT ["/mercurio"]
CMD ["serve", "--bind", "0.0.0.0:8000"]
