# Multi-platform manifest digest for python:3.12.16-slim-bookworm, resolved 2026-11-08.
FROM python:3.12.16-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df

ARG SOURCE_DATE_EPOCH=0
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

LABEL org.opencontainers.image.source="https://github.com/sf-matt/k8s-sec-stack" \
      org.opencontainers.image.title="k8s-sec-event-sink" \
      org.opencontainers.image.description="Bounded runtime-event and posture sink for k8s-sec-stack" \
      org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app
COPY src/ /app/src/

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["python", "-m", "k8s_sec_event_sink.server"]
