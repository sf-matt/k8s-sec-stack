# Multi-platform manifest digest for python:3.12.11-slim-bookworm, resolved 2026-08-30.
FROM python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7

ARG SOURCE_DATE_EPOCH=0
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

WORKDIR /app
COPY src/ /app/src/

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["python", "-m", "k8s_sec_event_sink.server"]
