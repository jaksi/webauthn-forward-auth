# webauthn-forward-auth

 Hacky, probably insecure, simple webauthn forward auth proxy

## Caddy

```Caddyfile
auth.example.com {
  reverse_proxy 127.0.0.1:8080
}

test.example.com {
  forward_auth 127.0.0.1:8080 {
    uri /auth
    copy_headers X-Webauthn-User
  }
  respond "Hello {header.X-Webauthn-User}!"
}
```

 ## Config

Use `/register` to register users and credentials (passkeys), use server logs to create a config like so:

 ```json
[
  {
    "id": "...",
    "name": "jaksi",
    "credentials": [
      {
        "id": "...",
        "publicKey": "...",
        "attestationType": "none",
        "transport": null,
        "flags": {
          "userPresent": true,
          "userVerified": true,
          "backupEligible": true,
          "backupState": true
        },
        "authenticator": {
          "AAGUID": "...",
          "signCount": 0,
          "cloneWarning": false,
          "attachment": ""
        },
        "attestation": {
          "clientDataJSON": "...",
          "clientDataHash": "...",
          "authenticatorData": null,
          "publicKeyAlgorithm": 0,
          "object": "..."
        }
      },
      {
        "id": "...",
        "publicKey": "...",
        "attestationType": "none",
        "transport": null,
        "flags": {
          "userPresent": true,
          "userVerified": true,
          "backupEligible": false,
          "backupState": false
        },
        "authenticator": {
          "AAGUID": "...",
          "signCount": 0,
          "cloneWarning": false,
          "attachment": ""
        },
        "attestation": {
          "clientDataJSON": "...",
          "clientDataHash": "...",
          "authenticatorData": null,
          "publicKeyAlgorithm": 0,
          "object": "..."
        }
      }
    ]
  }
]
```
