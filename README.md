# Pith POPRF

This repository implements a threshold-computable partially-oblivious pseudo-random function (POPRF)
with evaluations that are verifiable by the client.

Building upon the existing [BLS threshold signature based OPRF] implemented for use on Celo in
[ODIS], this repository implements an extension to the [Pythia] POPRF specification to provide
threshold computation and verification against a single pre-shared public key. This construction is
called Pith for its basis on Pythia and usage in the Celo PIN/Password Encrypted Account Recovery
protocol [PEAR].

At a high level, the POPRF is a protocol with a client and a service who collectively compute a keyed
PRF (i.e. essentially a hash) over a tag input and a message input. The message input is secret to
the client, and the private key input is secret to the service. In order to compute the final
function the client "blinds" the message and sends it, along with the tag, to the service. The
service may choose to compute the POPRF function over this blinded message and plaintext tag,
resulting in a blinded evaluation. This is sent back to the client, who unblinds the evaluation to
get the final output. More details are available in the specification below.

<!-- TODO(victor) Replace this link with a link to the CIP when published as a CIP -->
#### [Specification](https://clabsco.notion.site/POPRF-Cryptography-Construction-493f1099460940f8a5d7dee4c78b4442)

The specification linked above is also available in this repository as [specification.md](./specification.md).

### Applications

Some applications of (P)OPRFs include:

- Password hardening
  - [Pythia]
  - [OPAQUE]
  - [WhatsApp E2EE Backups]
- Anonymous credentials
  - [Pretty Good Phone Privacy]
  - [Privacy Pass]
- Private set intersection
  - [ODIS]

## WASM bindings

This library provides WASM bindings for signing under the `ffi/wasm.rs` module. These can be built
via the [`wasm-pack`](https://github.com/rustwasm/wasm-pack) tool. Depending on the platform you are
targeting, you'll need to use a different build flag.

Note: You can also replace `celo` with your own NPM username to test publish.

```bash
# Builds the WASM and wraps it as NPM package @celo/poprf
wasm-pack build --target nodejs --scope celo -- --features=wasm
```

The bundled WASM package will be under the `pkg/` directory. You can then either pack and publish it
with `wasm-pack`'s `pack` and `publish` commands, or manually import it in your application.

```bash
wasm-pack publish --access public
```

### TypeScript usage

Here is an example of using the library. In practice there will be a client and a server, with the
assumption that the client holds the message and the server holds the private key. In this snippet,
both client and server are represented.

```typescript
import * as poprf from '@celo/poprf'
import 'crypto'

const message = Buffer.from("message")
const tag = Buffer.from("tag")

// Generate a local keypair for demonstration purposes.
const keypair = poprf.keygen(crypto.randomBytes(32))

// Client: Blind the message to send to the server.
const { blindedMessage, blindingFactor } = poprf.blindMsg(message, crypto.randomBytes(32))

// Server: Evaluate the POPRF over the blinded message and tag.
const response = poprf.blindEval(keypair.privateKey, tag, blindedMessage)

// Client: Unblind and verify the evaluation returned from the server.
const result = poprf.unblindResp(keypair.publicKey, blindingFactor, tag, response)
```

<!-- Links -->
[BLS threshold signature based OPRF]: https://github.com/celo-org/celo-threshold-bls-rs
[ODIS]: https://docs.celo.org/celo-codebase/protocol/odis
[OPAQUE]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-opaque/
[PEAR]: https://docs.celo.org/celo-codebase/protocol/identity/encrypted-cloud-backup
[Pretty Good Phone Privacy]: https://www.usenix.org/conference/usenixsecurity21/presentation/schmitt
[Privacy Pass]: https://privacypass.github.io/
[Pythia]: https://eprint.iacr.org/2015/644.pdf
[WhatsApp E2EE Backups]: https://engineering.fb.com/2021/09/10/security/whatsapp-e2ee-backups/
