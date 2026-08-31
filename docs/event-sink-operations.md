# Event-sink operations

The event sink stores sensitive Kubernetes runtime evidence. Treat its database,
bearer tokens, scan reports, and generated local MCP configuration as sensitive.

## Container publication

The `Event sink image` GitHub Actions workflow builds and scans the image before
publishing multi-platform `linux/amd64` and `linux/arm64` manifests to
`ghcr.io/sf-matt/k8s-sec-event-sink`. Actions are pinned to immutable commits.
The published image includes an SBOM and build-provenance attestations. Workflow
run `33358389880` passed the blocking scan and published the public manifest:

```text
ghcr.io/sf-matt/k8s-sec-event-sink@sha256:ecd8cf86a6284ccaed6a9ee63c363f0d04fa01b65e43c327af01b9a576131479
```

GitHub Container Registry packages are private on first publication even when
their source repository is public. After the first successful workflow run, a
package administrator must open the package settings, set visibility to Public,
and confirm that the package is linked to `sf-matt/k8s-sec-stack`. The OCI source
label and repository workflow establish that link.

The chart records that multi-platform manifest in `eventSink.image.digest`.
Future releases must copy the digest from the workflow annotation into the
chart; the tag exists for discovery and local development only.

## Credential rotation

The sink, falcosidekick, and local MCP client read credentials at process start.
Updating the Secret alone does not rotate running processes. Rotation therefore
requires a short maintenance window:

1. Generate two independent random values of at least 128 bits. Never reuse the
   ingest token as the query token.
2. Update `mcp-event-sink-auth` atomically with `EVENT_SINK_INGEST_TOKEN`,
   `EVENT_SINK_QUERY_TOKEN`, and `WEBHOOK_CUSTOMHEADERS`. The header value must be
   `Authorization:Bearer <ingest-token>`.
3. Restart both deployments:

   ```bash
   kubectl -n security rollout restart deployment/mcp-event-sink deployment/falcosidekick
   kubectl -n security rollout status deployment/mcp-event-sink
   kubectl -n security rollout status deployment/falcosidekick
   ```

4. Rerun `./hack/configure-local.sh` and restart the MCP client so it receives the
   new query token.
5. Verify that the new credentials work and the old credentials receive HTTP 401.

Do not delete and recreate the Secret: the Helm template preserves the current
Secret values during upgrades. For an operator-managed Secret, set
`eventSink.auth.create=false` and retain the required fixed Secret name and keys.

## Upgrade data migration

Schema version 0 is the original ConfigMap-based sink, which stored complete
Falco bodies. On first startup of the packaged sink, those legacy raw bodies are
irreversibly cleared because they predate the opt-in redaction policy. Normalized
columns and trend history remain. Back up the PVC only if policy permits retaining
that sensitive legacy data outside the running service.

When `storeRawEvents=false`, startup also clears any raw bodies retained during a
previous opt-in period, and query handling ignores nonempty raw columns as a
defense-in-depth control.
