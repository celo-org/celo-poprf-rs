# Celo POPRF

This repository implements a threshold-computable partially-oblivious pseudo-random function (POPRF)
with evaluations that are verifiable by the client.

<!-- TODO(victor) Replace this link with a link to the CIP when published as a CIP -->
### [Specification](https://www.notion.so/clabsco/POPRF-Cryptography-Construction-493f1099460940f8a5d7dee4c78b4442)

## WASM bindings

This library provides WASM bindings for signing under the `ffi/wasm.rs` module. These can be built
via the [`wasm-pack`](https://github.com/rustwasm/wasm-pack) tool. Depending on the platform you are
targeting, you'll need to use a different build flag.

Note: You can also replace `celo` with your own NPM username to test publish.

```bash
# Builds the WASM and wraps it as NPM package @celo/poprf
$ wasm-pack build --target nodejs --scope celo -- --features=wasm
```

The bundled WASM package will be under the `pkg/` directory. You can then either pack and publish it
with `wasm-pack`'s `pack` and `publish` commands, or manually import it in your application.

```bash
$ wasm-pack publish --access public
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
