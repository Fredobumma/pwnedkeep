# pwnedkeep

Your own Pwned Passwords API. `pwnedkeep` keeps a local copy of [Have I Been Pwned](https://haveibeenpwned.com/Passwords)'s Pwned Passwords and serves the same `/range` endpoint as `api.pwnedpasswords.com`, byte for byte, so anything that checks passwords against the public service can check them against yours by changing one URL. It also answers direct and bulk checks for your own services, and audits Active Directory hash dumps.

## Why

Rejecting passwords that have already leaked is standard practice; NIST's password guidelines ask for it. Most software does it by calling the public Pwned Passwords API over the internet. That breaks in some places:

- **Offline, air-gapped and regulated networks**, such as government, banking and healthcare, where servers can't call out.
- **When the service can't be reached.** In October 2026, [Uptime Kuma 2.x](https://github.com/louislam/uptime-kuma/issues/7946) couldn't complete its first-time setup when `api.pwnedpasswords.com` was unreachable: the check failed, and with it the setup, whatever the password.
- **When even a hash prefix shouldn't leave the network.** k-anonymity sends only five characters of a hash, but some policies allow nothing out at all.

Have I Been Pwned publishes the data for exactly this, along with an official downloader. What it leaves to you is serving it. The self-hosted servers that exist are small experiments, most untouched for years.

## Quick start

```sh
pip install pwnedkeep

# download the SHA-1 data straight from api.pwnedpasswords.com (about 2.2 billion hashes)
pwnedkeep download sha1.pwnd

# serve it
pwnedkeep serve --sha1 sha1.pwnd --port 8000
curl http://localhost:8000/range/5BAA6
```

Then point your software at it: `http://localhost:8000` in place of `https://api.pwnedpasswords.com`.

To keep it current, run the same `download` again, from cron for example. Each range is requested with the ETag it had last time, so ranges that haven't changed come back as `304` and are copied from the store you already have. The new store replaces the old one when it is complete, and a running server picks it up within 30 seconds, without a restart.

### Already have the data?

If you've downloaded it with the official [PwnedPasswordsDownloader](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader), import it instead. The single `pwnedpasswords.txt` file and the folder of per-range files both work:

```sh
pwnedkeep import pwnedpasswords.txt sha1.pwnd
```

### NTLM

For Windows and Active Directory, the same data comes as NT hashes:

```sh
pwnedkeep download ntlm.pwnd --mode ntlm
pwnedkeep serve --sha1 sha1.pwnd --ntlm ntlm.pwnd
```

An `ntlm.pwnd` next to the SHA-1 store is served without being named.

## The API

| | |
| --- | --- |
| `GET /range/{prefix}` | As `api.pwnedpasswords.com`: SHA-1 by default, NTLM with `?mode=ntlm`, padding with `Add-Padding: true`, the same headers and error messages |
| `POST /check` | `{"password": "…"}`, `{"sha1": "…"}` or `{"ntlm": "…"}` → `{"pwned": true, "count": 52372427}` |
| `POST /check/bulk` | Up to 10,000 hashes of one kind → a count for each |
| `GET /health` | The stores loaded, their size and age |
| `GET /metrics` | Prometheus metrics |
| `GET /openapi.json` | The full description |

`/check` is for your own services on your own network. Prefer sending a hash; a password sent there is hashed and neither stored nor logged.

The API is open by default, like the public one. Set `PWNEDKEEP_API_KEYS` to a comma-separated list of keys to require one on every request but `/health`, as `Authorization: Bearer <key>` or `X-Api-Key: <key>`.

## Use cases

- **Sign-up and password-change forms that reject breached passwords**, in identity providers such as authentik, Keycloak and lldap, and in your own apps, with nothing sent off-site.
- **Air-gapped and regulated networks**, where calling out isn't allowed.
- **Auditing existing accounts:**

  ```sh
  pwnedkeep audit ntlm.pwnd ntds-dump.txt
  ```

  reads lines of `user:nthash`, or the `user:rid:lmhash:nthash:::` that `secretsdump` and similar tools write, and lists the accounts whose current password has appeared in a breach.
- **Reliability:** your sign-up doesn't break when a third-party service is slow or blocked.
- **One-off checks:** `pwnedkeep lookup sha1.pwnd` prompts for a password and says whether it's been seen, without it touching the network.

## How it's stored

The data goes into a single file laid out for lookups: an index with one entry for each of the 2²⁰ five-character prefixes, then every hash in order as a fixed-size record, the hash without its first two bytes plus a 32-bit count. A range is one slice of the file and a single hash is a binary search inside it. The file is memory-mapped, so the operating system keeps the busy parts in RAM and the rest on disk.

A range of about 2,100 hashes, the current average, is formatted in under a millisecond, and a single-hash check takes about a microsecond. The SHA-1 store is about 48 GB for 2.2 billion hashes, against roughly 100 GB for the text the official downloader writes; the NTLM store is about 40 GB.

## Docker

```sh
docker build -t pwnedkeep .
docker run --rm -v pwned-data:/data pwnedkeep download /data/sha1.pwnd
docker run -d -p 8000:8000 -v pwned-data:/data pwnedkeep
```

The image serves `/data/sha1.pwnd`, and `/data/ntlm.pwnd` too if it's there.

## Configuration

| Variable | |
| --- | --- |
| `PWNEDKEEP_SHA1`, `PWNEDKEEP_NTLM` | The stores to serve, if not given as `--sha1` and `--ntlm` |
| `PWNEDKEEP_API_KEYS` | Keys to require, comma-separated |
| `PWNEDKEEP_RELOAD_SECONDS` | How often to look for a newer store file. Default 30 |
| `HOST`, `PORT` | Default `0.0.0.0` and `8000` |

## Development

```sh
uv venv && uv pip install -e . pytest ruff mypy
pytest && ruff check . && mypy
```

## License

MIT for the code. The Pwned Passwords data is Have I Been Pwned's, under its own terms; pwnedkeep downloads it from the public API, as the official downloader does. pwnedkeep is not affiliated with Have I Been Pwned.
