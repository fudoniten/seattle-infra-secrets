# seattle-infra-secrets

SOPS-encrypted Kubernetes `Secret` manifests for the Seattle cluster. Flux
syncs this repository and `kustomize-controller` decrypts the files in
`./secrets` as it applies them, so the plaintext never leaves the cluster.

Everything here is safe to commit: the values inside `data` and `stringData`
are encrypted to the cluster's age key before they ever hit the working tree.

## Layout

```
.
├── README.md                  this file
├── cluster.agekey.public      the cluster's age recipient (public half)
├── .sops.yaml                 which key to encrypt to, and which fields
├── flake.nix                  dev shell with sops, age and the CLI
├── scripts/
│   └── seattle-secret.clj     the CLI itself (Babashka)
└── secrets/                   one encrypted Secret per file
```

Only `./secrets` holds manifests. See [What Flux sees](#what-flux-sees).

## The cluster key

`cluster.agekey.public` is a standard X25519 age recipient (`age1...`, 62
characters). Its private half is `AGE-SECRET-KEY-1...`. Any reasonably recent
`sops` and `age` handle it; no plugins are needed.

## Adding a secret

### Using the dev shell (recommended)

```sh
nix develop
```

That puts `seattle-secret`, `sops`, `age` and `bb` on `$PATH`. The CLI
writes the manifest, encrypts it, and drops it in `./secrets`:

```sh
# a file — SSH key, keytab, service-account JSON, anything
seattle-secret add --namespace klaxon --file=/tmp/key-file.json klaxon-key-file

# prompted values, never echoed and never in shell history
seattle-secret add -n hermes --password --token=api-key hermes-secrets

# add a key to a secret that already exists (needs the private key)
seattle-secret set hermes-secrets --literal RCON_PASSWORD=swordfish

# encrypt a complete Secret manifest you wrote yourself
seattle-secret import /tmp/teslamate-secrets.yaml --force
```

Then commit and push; Flux picks it up on its next reconcile.

| Command | |
|---------|--|
| `add <name>` | create a new Secret (refuses to clobber an existing file) |
| `set <name>` | add or replace keys in an existing Secret |
| `import <file>` | encrypt a complete plaintext Secret manifest into `./secrets` |
| `show <name>` | decrypt and print (needs the private key) |
| `edit <name>` | open in `$EDITOR` via `sops`, re-encrypting on save |
| `list` | every secret, its namespace, and its keys |
| `check` | verify nothing is committed in plaintext |

Value options, repeatable, for both `add` and `set`:

| Option | |
|--------|--|
| `--password[=KEY]` | prompt with confirmation (default key `password`) |
| `--token[=KEY]` | prompt once (default key `token`) |
| `--file [KEY=]PATH` | read a file; `KEY` defaults to the basename |
| `--literal KEY=VALUE` | take the value from the command line |

`--literal` lands in your shell history — prefer `--password` / `--token` for
anything that matters.

Run `seattle-secret --help` for the rest.

### Changing an existing secret

Each value in a Secret is its own key, so "add one more password to
`teslamate-secrets`" is just another key:

```sh
seattle-secret set teslamate-secrets --password=mqtt-password
```

`set`, `show` and `edit` decrypt the current file first, so they need the
private key (see [Reading a secret back](#reading-a-secret-back)). Without it,
write the whole manifest out again with every value in it and use `import`:

```sh
seattle-secret import /tmp/teslamate-secrets.yaml --force
```

`import` takes a plaintext `Secret` (or `-` for stdin), checks that it has a
name, a namespace and string values, and writes it encrypted to
`secrets/<metadata.name>.yaml` (`-o` to pick another filename). It refuses to
overwrite an existing file unless you pass `--force`. Running it on an
unencrypted file already in `secrets/` encrypts that file in place. It does not
delete the plaintext source, so remember to.

### Doing it by hand

The CLI is a convenience, not a requirement. To write a manifest yourself:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: <secret-name>
  namespace: <namespace>
type: Opaque
stringData:
  token: the-actual-secret-value
```

Then encrypt it in place. `.sops.yaml` already names the recipient and the
fields to encrypt, so no `--age` or `--encrypted-regex` flags are needed as
long as the output path is under `secrets/`:

```sh
sops encrypt --in-place secrets/<secret-name>.yaml
```

**Use `stringData`, not `data`.** Kubernetes base64-encodes `stringData` for
you. The old instructions in this repo said to run `echo "secret" | base64`
and paste the result into `data:` — `echo` appends a newline, so that encodes
`secret\n` and the application receives a value with a stray newline on the
end. This usually surfaces much later as an authentication failure with no
obvious cause.

If you do need `data` — binary content such as a keytab, where `stringData`
cannot represent the bytes — encode without the trailing newline:

```sh
base64 -w0 < /path/to/file
```

The CLI encodes `--file` with `java.util.Base64` (no line breaks, no added
newline) and puts everything else in `stringData`, which is why it does not
have this problem. `import` warns when a `data` value decodes to something
ending in a newline.

Both fields are covered by the `encrypted_regex` in `.sops.yaml`, so either
way the values get encrypted and the metadata stays readable in diffs.

## Reading a secret back

You need the private key, which lives on the cluster and in your password
store — it is not in this repository. Point `sops` at it:

```sh
export SOPS_AGE_KEY_FILE=~/.config/sops/age/seattle.key
seattle-secret show hermes-secrets
```

Without an identity you can still create secrets with `add` and `import`, but
you cannot read existing ones back or change them with `set` or `edit`. The
dev shell warns when no identity is configured.

## What Flux sees

The `seattle-infra-secrets` `Kustomization` in `seattle-infra` uses
`path: ./secrets`, so only that directory is applied. `README.md`,
`flake.nix`, `flake.lock`, `.sops.yaml` and `scripts/` are never read as
manifests. Keep `./secrets` to encrypted `Secret` files only: any other YAML in
it fails the whole reconcile.

The `Kustomization` decrypts with the `sops-age` Secret in `flux-system`, which
holds the `AGE-SECRET-KEY-1...` identity under a `.agekey` key. That resource
lives in the cluster config, not here.

## Rotating the cluster key

1. `age-keygen -o seattle.key`.
2. Put the new public half in `cluster.agekey.public` and in the `age:` field
   of `.sops.yaml`. `seattle-secret check` fails if the two disagree.
3. Re-encrypt everything to the new recipient, with the *old* key still
   available so `sops` can read the current contents:

   ```sh
   for f in secrets/*.yaml; do sops updatekeys --yes "$f"; done
   ```
4. Update the `sops-age` Secret in the cluster **before** pushing, or Flux
   will not be able to decrypt what it fetches.

## Checking your work

```sh
seattle-secret check
```

This verifies that `.sops.yaml` and `cluster.agekey.public` still agree, and
that every file in `secrets/` is encrypted, is a `Secret`, and names a
namespace. It is worth running before you push — it catches a plaintext file
committed by accident, which is the mistake that actually costs something.

## Hacking on the CLI

`scripts/seattle-secret.clj` is a [Babashka](https://babashka.org) script.
It is executable and self-contained, so nix is optional — with `bb` and `sops`
on your `$PATH` it runs straight from the tree:

```sh
./scripts/seattle-secret.clj list
```

It shells out to exactly two commands, `git` and `sops`. YAML is parsed and
emitted with Babashka's built-in `clj-yaml`, which is what keeps values like
`*star` or a password containing a newline correctly quoted — the script never
does its own escaping. Secret values are held in memory and passed to `sops` on
stdin, so no plaintext is written to disk at any point.

`nix flake check` runs `clj-kondo` over it. Set `SEATTLE_SECRETS_DIR` to run it
against a checkout other than the one you are standing in.
