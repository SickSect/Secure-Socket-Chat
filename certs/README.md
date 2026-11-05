# Development certificates

Generated files in this folder are **ignored by git** (only this README and the
generator script are tracked). Never commit keystores, private keys or generated
certificates.

For local development, generate a self-signed server certificate and a client
truststore with:

```powershell
# from the repository root
powershell -ExecutionPolicy Bypass -File certs/generate-dev-certs.ps1
```

The script uses the password `changeit` by default. To use another password:

```powershell
powershell -ExecutionPolicy Bypass -File certs/generate-dev-certs.ps1 -Password "my-dev-password"
```

Then set the same value in `.env`:

```dotenv
TLS_KEYSTORE=certs/server-keystore.p12
TLS_KEYSTORE_PASSWORD=changeit
TLS_KEY_PASSWORD=changeit
TLS_TRUSTSTORE=certs/client-truststore.p12
TLS_TRUSTSTORE_PASSWORD=changeit
```

Files produced:

| File | Purpose |
|------|---------|
| `server-keystore.p12` | private key + certificate used by the Spring HTTPS server and the TCP chat server |
| `server.crt` | public certificate (can be deleted after generation) |
| `client-truststore.p12` | trust anchor used by the chat client and REST client |

The certificate contains `SAN=dns:localhost,ip:127.0.0.1`, so the client's
hostname verification (`endpointIdentificationAlgorithm=HTTPS`) succeeds when
connecting to `localhost`.

## Production

Do **not** use this script in production. Use a certificate issued by a real
CA (for example Let's Encrypt), protect the keystore password, and distribute
only the CA certificate to clients. The client truststore must never contain
the server's private key.
