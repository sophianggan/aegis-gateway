# Supply-chain evidence

Every `main` build audits installed dependencies, builds the runtime container, produces a
CycloneDX SBOM, builds the Python wheel, and uploads a checksummed evidence bundle. The
bundle manifest binds each artifact to the exact Git revision and records its SHA-256
digest and byte size.

The evidence job does not publish packages or images. Promotion remains a separate,
reviewed action so an ordinary source push cannot mutate a deployment registry.

## Verification

Download the `supply-chain-evidence` artifact from the corresponding workflow run and
verify a file against the manifest:

```bash
python - <<'PY'
import hashlib, json, pathlib

manifest = json.loads(pathlib.Path("evidence-manifest.json").read_text())
for artifact in manifest["artifacts"]:
    path = pathlib.Path(artifact["path"])
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    assert actual == artifact["sha256"], path
print(f"verified {len(manifest['artifacts'])} artifacts")
PY
```

For a release, retain the workflow URL, commit SHA, evidence artifact, image registry
digest, and deployment approval together. GitHub artifacts have finite retention; copy
release evidence to the organization's immutable evidence store before expiry.

