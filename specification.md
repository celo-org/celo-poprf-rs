# Pith POPRF Specification

- Table of contents

## Background

ODIS currently provides a rate-limited PRF service with the primary use case of supporting rate-limited discovery of Celo addresses from a user's phone number. In order to support secure password hardening and future use cases, granular rate limits are invaluable. Applying rate limits on a per-user basis (e.g. restricting the number of guesses on a user's password to a constant number) ODIS's OPRF scheme must be extended to support domain separation between users in a way that that is visible to the service to inform rate limiting rules. In [ia.cr/2018/733](http://ia.cr/2018/733), a construction that satisfies this need is described as a partially oblivious pseudo-random function (POPRF) 

ODIS currently exists as a decentralized verifiable OPRF service based on blind threshold BLS signatures. Building upon this foundation, we aim to create a decentralized and verifiable POPRF service. Doing so enables users to apply the core primitive of ODIS, a rate limited PRF service, to new applications with the same trust assumptions rooted in the collective honesty of the ODIS operators.

### Goals

In order to extend ODIS to support POPRF computation, with the primary use case of password hardening, we aim to create a POPRF construction with a combination of properties not natively available to any proposed scheme published to date. In particular, the POPRF should be:

- Computable in a threshold MPC process. Ideally without interaction between operators.
- Verifiable against a pre-shared key.

Supporting thresholdization, as compared to relying on a single party to compute the POPRF function, supports the decentralized trust model required for many applications of ODIS as a public service supporting Celo. It must be the case that no single party can unilaterally compute the POPRF function, thereby breaking rate limiting, or censor requests from an honest client. ODIS currently does not require interaction between the operators, relying instead only on communication between each operator and the client. This is a desirable property as it greatly simplifies service operation, performance, and reliability.

Supporting verifiability against a pre-shared key (e.g. packaged with the binary) allows clients ensure that no bad actor among the decentralized operators can corrupt the output of the POPRF without being detected. This is as opposed to the verifiability of a the (P)OPRF construction used in OPAQUE, where it is verifiable but uses client-specific keys which then requires client-state and disallows verification of the first interaction with the service.

### Source research

[The Pythia PRF Service](http://ia.cr/2015/644)

[Threshold Partially-Oblivious PRFs with Applications to Key Management](http://ia.cr/2018/733)

[OPAQUE: An Asymmetric PAKE Protocol Secure Against Pre-Computation Attacks](http://ia.cr/2018/163)

[A Fast and Simple Partially Oblivious PRF, with Applications](https://ia.cr/2021/864)

# Proposed protocol

Proposed below is an adaptation of the Pythia construction to achieve the thresholdization and verifiability properties described above. It includes a threshold computation method not present in the original work, as well as an interactive verification protocol inspired [ia.cr/2018/733](http://ia.cr/2018/733).

# Single-Party Variant

We start by describing the POPRF protocol as computed by a single party.

## Setup

As global parameters, the protocol uses three groups $\mathbb{G}_1$, $\mathbb{G}_2$, and $\mathbb{G}_T$ of prime order $p$ with an efficiently computable asymmetric pairing $e: \mathbb{G}_1\times\mathbb{G}_2\to\mathbb{G}_T$. Generators for these groups are respectively written as $g_1$, $g_2$, and $g_T$. In practice this is provided by [BLS12-377](https://eprint.iacr.org/2018/962.pdf).

Service $S$ choses private key $k \in \mathbb{Z}_p$ uniformly at random and publishes public key $v=g_2^k$

Client $C$ holds the public key $v$, secret message input $m$, and non-secret domain "tag" $t$.

The protocol implements POPRF functionality $F_k(t,m)$.

## POPRF Protocol

- $C$ samples $r \leftarrow_R\mathbb{Z}_p$ and calculates blinded input $x=H_2(m)^r$

- $C$ sends $(t, x)$ to $S$
- $S$ calculates $Y=e(H_1(t)^k, x)\in\mathbb{G}_T$
- $S$ sends $Y$ to the $C$
- $C$ computes the unblinded output $y=Y^{r^{-1}}=e(H_1(t),H_2(m))^k$

### **Comparison to Pythia**

Note that the output of this protocol is derived from the POPRF function of [Pythia](https://eprint.iacr.org/2015/644.pdf),  $F_k(t,m)=e(H_1(t),H_2(m))^k$, with the following differences in computation.

- User selector $w$ is omitted from the protocol, and a single key is instead used for all applications. Deriving per-application keys via an HMAC, as is done in Pythia, is incompatible with practical thresholdization. As there is a single “application” in our construction, and the selector is omitted from formal proofs of Pythia’s security, this does not invalidate any of the formal security guarantees.
- User selector $w$ is omitted from the protocol, and a single key is instead used for all applications. Deriving per-application keys via an HMAC, as is done in Pythia, is incompatible with practical thresholdization. As there is a single “application” in our construction, and the selector is omitted from formal proofs of Pythia’s security, this does not invalidate any of the formal security guarantees.
- The service $S$ does not generate a proof of discrete logarithm. Verifiability of the output is instead provided by the interactive protocol described below.
- The service does not return the public key to the user as part of POPRF evaluation. It is assumed that the client already has a copy of the service public key $v$.

These modifications coincide with the version formally analyzed in appendix B of the Pythia paper, which also removes the key selector and proof of discrete logarithm. As a result the security properties proofs of unpredictability and pseudo-randomness, as defined by the authors, apply to the POPRF protocol above.

## Interactive verification protocol

- $C$ samples $(r,c,d) \stackrel{\$} {\leftarrow}\mathbb{Z}_p^3$
- $C$ computes $h = H_2(m)$ and $a = h^r \in \mathbb{G}_2,\  b=h^cg_2^d  \in \mathbb{G}_2$
- $C$ sends $(a,b)$ to $S$
- $S$ calculates $A=e(H_1(t)^k, a)  \in \mathbb{G}_T,\ B=e(H_1(t)^k,b)  \in \mathbb{G}_T$
- $S$ sends $(A, B)$ to $C$
- $C$ checks that $A^{r^{-1}} \stackrel{?}{=} B^{c^{-1}}e(H_1(t),v^{-dc^{-1}})$
- If the check passes, $C$ accepts $A^{r^{-1}}$ as  the value $F_k(t,m)=e(H_1(t),H_2(m))^k$

Note that from the service perspective, this is equivalent to two queries executed in parallel.

### Proof sketch

- Write the hash-to-curve output as $H_1(t)=g_1^{l_t},\ H_2(m)=g_2^{l_m}$, for some unknown $l_t,l_m$.
- Denote the keys effectively used to compute $A$ and $B$ respectively as $k_A,\ k_B$
    - Note that, because the server may return arbitrary elements $A,\ B\in\mathbb{G}_T$ the "effective" keys $k_A,\ k_B$ may be unknown.
- $A=e(H_1(t),a^{k_A})=e(g_1^{l_t},H_2(m)^{rk_A})=e(g_1^{l_t},g_2^{l_mrk_A})=g_T^{l_tl_mrk_A}$
- $B=e(H_1(t),b^{k_B})=e(g_1^{l_t},(H_2(m)^cg_2^d)^{k_B})=e(g_1^{l_t},g_2^{(l_mc+d)k_B})=g_T^{(l_mc+d)l_tk_B}$
- $A^{r^{-1}}=g_T^{l_tl_mk_A}$
- $B^{c^{-1}}e(H_1(t),v^{-dc^{-1}})=g_T^{(l_mc+d)l_tk_Bc^{-1}}e(g_1^{l_t},g_2^{-dc^{-1}k})=g_T^{(l_mc+d)l_tk_Bc^{-1}-dc^{-1}l_tk}$
- In the exponent, the verification equation becomes
- $l_tl_mk_A\stackrel{?}{=}(l_mc+d)l_tk_Bc^{-1}-dc^{-1}l_tk=l_tl_mk_B+dc^{-1}l_tk_B-dc^{-1}l_tk=l_tl_mk_B+dc^{-1}l_t(k_B-k)$

This equation holds when $k_A=k_B=k$, or when $k_A-k_B=dc^{-1}l_m^{-1}(k_B-k)$. Because $d$ and $c$ are perfectly hidden, an attacker has probability at most $1/p$, where $p$ is the group order, of tricking the client.

Note that there is also a trivial solution when $H_1(t)=O \rightarrow l_t=0$. Although standard [hash-to-curve](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/) functions may return the identity element, they do so with negligible probability ($1/p$) and it considered computational infeasible to find such a pre-image. 

**Comparison to the work of Jarecki, Krawcyk, and Resch**

This interactive verification protocol is inspired by a similar construction in [ia.cr/2018/733](http://ia.cr/2018/733) section 4. Because the POPRF function is distinct from the one presented in that work, the verification equation is also distinct. The POPRF function, and therefore the verification equation, presented here includes a pairing and second hash-to-curve function which are not included in the verification protocol of [ia.cr/2018/733](http://ia.cr/2018/733).

**Motivation for the interactive verification protocol**

The interactive verification protocol above achieves two goals when combined with the threshold construction described below:

1. It does not require interaction between the service operators.
2. It allows the client to verify a combined output against the service key without needing to obtain the individual responses and public keys for each service operator.

The primary alternative to this interactive verification scheme is to produce an NIZK proof of discrete logarithm equality between the response message $y$ and the public key $v$. We have not chosen this approach because it either requires a proof to be sent along with each operator's response, and to have that proof verified against an operator specific public key, or to have the operators coordinate to produce a collective proof against the combined output and service public key in a protocol similar to threshold Schnorr signatures (e.g. [FROST](https://crysp.uwaterloo.ca/software/frost/)).

### Note on rate limiting

In applications such as password hashing or [privacy preserving authentication](https://privacypass.github.io/) the main purpose of using a (P)OPRF protocol is to allow the service to enforce some rate-limiting function on evaluations of the underlying PRF. Each evaluation request much be counted against a quota as defined by the application, and it important that this quota acts as an upper bound for how many evaluations can be obtained.

Because the two blinded query elements used in the verification protocol are indistinguishable from queries against distinct messages, each request must count individually against the rate limit. As a result, the rate limit observed by a given user who verifies all responses will be *half* of what the ruleset specifies (e.g. if the user makes 5 verified queries in a given tag, they will consume 10 requests worth of quota).

In the "Proof of related query for verification" section below, we attempt to address this challenge by adding a proof sent from the client $C$ to the service $S$ showing that the two queries cannot be used to compute distinct POPRF outputs.

## Standardized protocol definition

Here we present a formalized protocol interface, following the syntax presented in [ia.cr/2021/864](https://eprint.iacr.org/2021/864.pdf). This interface is intended to be helpful in understanding the proposed protocol, and will be used below as well.

The protocol presented above is formalized as a tuple of algorithms:

$$
\text{POPRF}=(\text{Req}, \text{BlindEv}, \text{Finalize},\text{Ev})
$$

$$
\underline{\text{POPRF.Req}(v,t,m)\rarr(st,req):}\\
(r,c,d) \stackrel{\\\$} {\leftarrow}\mathbb{Z}_p^3\\
h \larr H_2(m) \in \mathbb{G}_2\\
(a,b) \larr (h^r,\  h^cg_2^d)\\
\text{return}\ ((t,r,c,d),(a,b))
$$

$$
\underline{\text{POPRF.BlindEv}(k,t,req) \rarr rep:}\\
(a,b) \larr req \in \mathbb{G}_2^2\\
A \larr e(H_1(t)^k, a)\\
B \larr e(H_1(t)^k, b)\\
\text{return}\ (A,B)
$$

$$
\underline{\text{POPRF.Finalize}(v,rep:st) \rarr y:}\\
(A,B) \larr rep \in \mathbb{G}_T^2\\
(t,r,c,d) \larr st\\
y_A \larr A^{r^{-1}}\\
y_B \larr B^{c^{-1}}e(H_1(t),v^{-dc^{-1}})\\
\text{require}\ y_A \stackrel{?}{=} y_B\\
\text{return}\ (y_A)
$$

$$
\underline{\text{POPRF.Ev}(k,t,m) \rarr y:}\\
y \larr e(H_1(t)^k, H_2(m))\\
\text{return}\ y
$$

## Proof of related query for verification

As mentioned above, the interactive verification protocol requires two blinded queries against the POPRF service, which results in a single verified query being counted against the rate limit twice. If the client can prove they can calculate at most one distinct output from the two blinded inputs, then they can be counted against the rate limit only once.

If the client knows some relation between $a$ and $b$ of the interactive proof protocol (i.e. knows some $x,y\in Z_p^2$ such that $a^xg_2^y=b$.), then they can calculate the POPRF output for blinded input $b$ from the output for blinded input $a$. More specifically, given $A=e(H_1(t),a)^k$, they could calculate:

$$
 A^x e(H_1(t),v^y)=e(H_1(t),a^x)^ke(H_1(t),g_2^y)^k=\\
e(H_1(t),a^{x}g_2^y)^k=e(H_1(t),b)^k=B
$$

When $a$ and $b$ are calculated as in the POPRF verification protocol above $x=\frac{c}{r},\ y=d$.

As a result, providing the client with $B$ provides no additional information if they already have $A$ and know the relation between $a$ and $b$. If the client can prove to the service that they know such a relation, then the service can respond to both queries without providing the client any new information that could be used to forge an evaluation over a distinct message, or otherwise compromise the rate limiting of the POPRF.

Below we define a non-interactive proof of knowledge protocol that allows the client to prove to the server they know such a relation. Once the server verifies this proof from the client, they provide a response to both blinded inputs provided by the client while accounting for this as one request, since they can only be used to calculate one distinct output.

### Protocol

This protocol is built from [RFC 8325](https://datatracker.ietf.org/doc/html/rfc8235) Schnorr NiZK proofs, including the modification described in [section 4](https://datatracker.ietf.org/doc/html/rfc8235#section-4) of sending the commitment value $z$ instead of the group element.

$$
\text{Rel}=(\text{Prove}, \text{Verify})
$$

$$
\underline{\text{Rel.Prove}(a,b,x,y) \rarr \pi :}\\
v_1, v_2 \stackrel{\$}{\leftarrow} \mathbb{Z}_p^2\\
V \larr g_2^{v_1} a^{v_2} \in \mathbb{G}_2\\
z \larr H(g_2 || V || a || b) \in \mathbb{Z}_p\\
s_1 \larr v_1 - y \cdot z\\
s_2 \larr \ v_2 - x \cdot z\\
\text{return}\ (z,s_1,s_2) \in \mathbb{Z}_p^3
$$

$$
\underline{\text{Rel.Verify}(a,b,\pi) \rarr \{0,1\}:}\\
z,s_1,s_2 \larr \pi \in \mathbb{Z}_p^3\\
V \larr g_2^{s_1}a^{s_2}b^z \in \mathbb{G}_2\\
\text{return}\ z \stackrel{?}{=} H(g_2 || V || a || b)
$$

[Proof of Related Query Sigma Protocol](https://www.notion.so/Proof-of-Related-Query-Sigma-Protocol-d27186f6057b4c1abbae1b660a6e5a52)

As part of a POPRF query, in addition to $req=(a,b)$, the client $C$ sends $\pi = \text{Rel.Prove}(a,b,\frac{c}{r},d)$ to the service $S$. If $\text{Rel.Verify}(a,b,\pi)\stackrel{?}{=}1$, they $S$ respond with an evaluation over both blinded input elements $a$ and $b$ while counting against the quota as one request.

### Proof sketch

- Completeness:
    - $g_2^{s_1}a^{s_2}b^z = g_2^{v_1 - y \cdot z} a^{v_2 - x \cdot z} b^z = g_2^{v_1}a^{v_2}g_2^{-y \cdot z}a^{-x \cdot z}b^z=V((g_2^{y}a^{x})^{-1}b)^z=V(b^{-1}b)^z = V$
- Proof of knowledge:
    - The extractor can work similarly to Schnorr - rewind $C$ and choose a different value in the random oracle for $z$. Then the exponents $x, y$ can be recovered using $x=\frac{{s_2}_1-{s_2}_2}{z_1 - z_2},y=\frac{{s_1}_1-{s_1}_2}{z_1 - z_2}$
- Zero-knowledge:
    - Similar to Schnorr - the simulator chooses $s_1, s_2, z \stackrel{\$}{\larr} \mathbb{Z}_p, V=g_2^{s_1}\cdot a^{s_2}\cdot b^{z}$. We then have $V=g_2^{s_1}a^{s_2}b^z$.

### Interaction with the POPRF protocol

It is important that adding the NiZK proof $\pi$ to a POPRF query does not compromise any of the security properties of the POPRF.
In the case of uniqueness and randomness, which assume a malicious client, there is no loss of security because the proofs and their verification result can be calculated entirely from information known to the client. In particular, an adversary given access to an oracle for $\text{POPRF.BlindEv}(k,\cdot,\cdot)$ can perfectly simulate a version of the same oracle with the addition of its response being conditional on checking the NiZK proof $\pi.$ As a result, the adversary gains no advantage from the addition of the client generated NiZK or the server's verification of it.

In the case of unlinkability, which assumes a malicious service, there is no loss of security because the proof is constructed from the blinded inputs, and hides any information about the relation between them (e.g. the blinding factors) due to the proofs zero-knowledge property.

# Multi-Party variant

In order to facilitate a decentralized trust assumption, the protocol above is adapted to threshold computation across a number of parties holding shares of the service key.

Instead of a single party, $n$ parties $S_i$ for $i\in\{1 \dots n\}$ collectively act as the logical service $S$. In the threshold computation, any $\tau$ parties may collectively compute the POPRF function $F_k(t,m)$. Any set of parties of size less than $\tau$ must not be able to compute the function with greater than negligible probability.

## Distributed key generation

During a setup phase, the parties participate in a Pedersen DKG, as described in [Gennaro et. al. 2007](https://link.springer.com/article/10.1007/s00145-006-0347-3). As output of this ceremony, each party $S_i$ holds key share $k_i = f(i)$ where $f\in\mathbb{Z}_p[x]$ is a polynomial of degree $\tau-1$ such that $f(0)=k$. The service public key is $v=g_2^{f(0)}$ accordingly.

### **Security of the POPRF with respect the the Pedersen DKG**

As shown by  [Gennaro et. al.](https://link.springer.com/article/10.1007/s00145-006-0347-3), a dishonest participant may bias the output of the Pedersen DKG. As a result, proofs of security under an assumption of fully random key generation cannot be guaranteed to apply when keys are instead generated through the Pedersen DKG. However, in specific cases it has been proven that the Pedersen DKG can be used without breaking existing proofs of a protocol's security. In particular, [ia.cr/2021/005](https://eprint.iacr.org/2021/005.pdf) shows that the Pedersen DKG, and other "key-expressable" DKGs, can be used to instantiate keys for "rekeyable" cryptographic schemes while preserving the validity of associated security proofs.

We show here that the POPRF evaluation and verification functions defined above are rekeyable with respect to the secret key as defined in [ia.cr/2021/005](https://eprint.iacr.org/2021/005.pdf) definition 5.

**Claim: $F_k(t,m)$ is rekeyable with respect to the secret key**

Given a POPRF evaluation $y=F_k(t,m)$ under key $k$ for known tag and message $(t,m)$, it is easy to compute the rekeyed evaluation $F_{k'}(t,m)$ under key $k'=\alpha k+\beta$ for arbitrary input values $(\alpha,\beta)\in\mathbb{Z}_p^2$.

$$
F_{k'}(t,m)=e(H_1(t),H_2(m))^{k'}=e(H_1(t),H_2(m))^{\alpha k+\beta}=e(H_1(t),H_2(m))^{\alpha k}e(H_1(t),H_2(m))^\beta=F_k(t,m)^\alpha e(H_1(t),H_2(m))^\beta=F_k(t,m)^\alpha F_\beta(t,m)
$$

This allows us to define the rekeying algorithm for $F_k(t,m)$

$$
\text{rekey}_F(\alpha,\beta,(t,m),F_k(t,m))=F_k(t,m)^\alpha F_\beta(t,m)
$$

Note that $\text{rekey}_F$ is invertible with $\text{rekey}_F^{-1}(\alpha,\beta,\cdot,\cdot)=\text{rekey}_F^{-1}(\frac{1}{\alpha},-\frac{\alpha}{\beta},\cdot,\cdot)$.

**Claim: $\text{POPRF.BlindEv}(k,t,req)$ us rekeyable with respect to the secret key**

Given a POPRF blind evaluation response $(A,B)$ under unknown key $k$ and known tag $t$ it is easy to compute the rekeyed response $(A',B')$ under key $k'=\alpha k+\beta$ for arbitrary input values $(\alpha,\beta)\in\mathbb{Z}_p^2$.

$$
⁍
$$

Calculation of $B'$ is defined similarly to yield the rekeying function:

$$
\underline{\text{rekey}_B(\alpha,\beta,(t,req),rep_k) \rarr rep_{k'}}\\
(a,b) \larr req\\
(A,B) \larr req_k\\
A' \larr A^\alpha e(H_1(t),a)^\beta\\
B' \larr B^\alpha e(H_1(t),b)^\beta\\
\text{return}\ (A',B')
$$

By construction

$$
\text{rekey}_B(\alpha,\beta,(t,req),\text{POPRF.BlindEv}(k,t,req))=\text{POPRF.BlindEv}(\alpha k+\beta,t,req)
$$

**Claim: $(\text{POPRF.BlindEv}(k,t,req),\text{POPRF.Finalize}(v,rep:st))$  is rekayable with respect to the secret key**

Given a POPRF blind evaluation response $rep_k=(A,B)$ under unknown key $k$ and known tag $t$ we use the rekey algorithm defined above to compute $rep_{k'}=(A',B')$ under key $k'=\alpha k+\beta$ for arbitrary input values $(\alpha,\beta)\in\mathbb{Z}_p^2$. Given the client state $st=(v,t,m,r,c,d)$ we show that the $\text{POPRF.Finalize}$ algorithm correctly verifies and unblinds the response under the constructed key $v'=v^\alpha g_2^\beta=g_2^{\alpha k+\beta}=g_2^{k'}$ such that

$$
\text{POPRF.Finalize}(v,req:st)=\text{rekey}_F^{-1}(\alpha,\beta,(t,m),\text{POPRF.Finalize}(v',\text{rekey}_B(\alpha,\beta,(t,req),rep_k)))
$$

First we show that the verification step of $\text{POPRF.Finalize}(v,req:st)$ passes iff the verification step of $\text{POPRF.Finalize}(v',\text{rekey}_B(\alpha,\beta,(t,req),rep_k))$ passes:

$$
A'^{r^{-1}}
=
B'^{c^{-1}}e(H_1(t),v'^{-dc^{-1}}) 
\Lrarr\\
(A^\alpha e(H_1(t),a)^\beta)^{r^{-1}}
=
(B^\alpha e(H_1(t),b)^\beta)^{c^{-1}}e(H_1(t),(v^\alpha g_2^\beta)^{-dc^{-1}})
\Lrarr\\
A^{\alpha r^-1}e(H_1(t),a^{r^{-1}})^\beta
=
B^{\alpha c^{-1}} e(H_1(t),b^{c^{-1}})^\beta e(H_1(t),v^{-\alpha dc^{-1}}g_2^{-\beta dc^{-1}})
=
B^{\alpha c^{-1}} e(H_1(t),b^{c^{-1}})^\beta e(H_1(t),v^{-\alpha dc^{-1}})e(H_1(t),g_2^{-\beta dc^{-1}})
=
B^{\alpha c^{-1}} e(H_1(t),(b\ g_2^{-d})^{ c^{-1}})^\beta e(H_1(t),v^{-\alpha dc^{-1}})
\Lrarr\\
A^{\alpha r^{-1}}e(H_1(t),H_2(m))^\beta
=
B^{\alpha c^{-1}} e(H_1(t),H_2(m))^\beta e(H_1(t),v^{-\alpha dc^{-1}})
\Lrarr\\
A^{\alpha r^{-1}}
=
B^{\alpha c^{-1}} e(H_1(t),v^{-\alpha dc^{-1}})
\Lrarr\\
A^{r^{-1}}
=
B^{c^{-1}} e(H_1(t),v^{-dc^{-1}})
$$

Next we show that the unblinding of the rekeyed response $A'$ results in the correct evaluation output of the POPRF functionality under the derived key $k'$.

$$
A'^{r^{-1}}=(A^\alpha e(H_1(t),a)^\beta)^{r^{-1}}=F_k^\alpha (t,m)e(H_1(t),H_2(m))^\beta=F_{k'}(t,m)
$$

As a result of the rekeyability of $(\text{POPRF.BlindEv}(k,t,req),\text{POPRF.Finalize}(v,rep:st))$ , and Lemma 5 [ia.cr/2021/005](https://eprint.iacr.org/2021/005.pdf), the use of the Pederson DKG does not compromise the uniqueness or unpredictability of the POPRF protocol.

## Threshold computation

When queried by $C$ with $(t, x)$, server $S_i$ responds with $Y_i=e(H_1(t)^{k_i},x)\in\mathbb{G}_T$ as specified above.

Upon receipt of  $\tau$ responses, the client $C$ or an untrusted relay computes $Y=\sum_{i\in I}Y_i^{\lambda_i(0)}$ where $I$ is a subset of the identifier values $i$ corresponding to the responding servers and $\lambda_i$ is the Lagrange polynomial such that $f(i)=1$ and $f(j)=0$ for $j\in I \setminus \{i\}$.

### Algorithm definition

In order to calculate this aggregation, we add the following algorithm to the POPRF protocol definition above:

$$
\underline{\text{POPRF.Aggregate}(I,\{rep_i \mid i\in I\})\rarr rep:}\\
\{(A_i, B_i)\larr rep_i \mid i \in I \}\\
A \larr \textstyle{\sum_{i\in I}A_i^{\lambda_i(0)}}\\
B \larr \textstyle{\sum_{i\in I}B_i^{\lambda_i(0)}}\\
\text{return}\ (A,B)
$$

### **Comparison to Pythia**

As defined in [ia.cr/2015/644](https://eprint.iacr.org/2015/644.pdf), Pythia does not specify a threshold computation strategy for the POPRF function. As a result the construction presented here is new and not covered by proofs in other works.

In Section 6.2, the authors do describe a client-side scheme for storing a secret protected by $k$ of $n$ Pythia servers. In the case of password encrypted backups, where durable storage is an inherent requirement, the method described is a viable strategy. This method can also be constructed from any verifiable POPRF scheme, and its security is derived directly from the existing properties of the POPRF. In this way, it is an attractive option. It does have some drawbacks in comparison with the construction presented here:

- It requires the client to durably store the non-secret "encrypted" polynomial coefficients. Although not an issue for encrypted backups, this may be a challenge for other applications of the proposed POPRF protocol.
- It requires the client to receive and verify the output of $n$ POPRF servers, as opposed to permitting a relayer to handle aggregation of partial POPRF outputs from individual servers. An untrusted relayer is often quite beneficial to save the resources of mobile clients.
- It is not possible for the servers to proactively reshare their keys, including to add or remove members of the committee, without involvement from the client. In the event that a server is compromised and removed from the committee, the client must be notified and they must compute a new polynomial after querying the new committee.

## Relayer

In order to simplify the client experience and reduce the client-side overhead, an untrusted relayer may be used to transmit the client request to each service operator and to aggregate the results.

In particular, the client $C$ sends their request including the tag $t$ and blinded input $x$ to the relayer $R$. The relayer then forwards the request to each of the $n$ service operators $S_i$ and accepts the blinded responses $Y_i$ from each. The relayer computes the polynomial interpolation described above to produce the combined output $Y$, and forwards this combined response to the user.

As long as the client verifies the results against the service public key $v$, the relayer cannot tamper with the response without detection. Additionally since the POPRF request and responses are perfectly blinded and unlinkable, the relayer learns nothing of the blinded input or output. Relayers could potentially deny service to clients, and so there should be an option to send requests directly to the service operators without the relayer whenever this is a concern. It is also the case that if the client detects a verification failures they cannot easily trace the cause or remove any bad output shares, since they will not have the direct responses from each service operator $S_i$.

Using a relayer allows the client to interact with the service as a whole without awareness of the individual signers. In particular, the client needs only the service public key $v$ and the internet address of the relayer, as opposed to needing the individual public keys and internet addresses of the service operators $S_i$ which may change over time. The client also does not need to compute the Lagrange interpolation of the service outputs, which is somewhat expensive when considering that the client is often on a mobile device and the output group elements are in $\mathbb{G}_T$.

# Complete protocol

## Setup

Parties $S_i$ for $i\in\{1 \dots n\}$ participate in a Pedersen DKG, as described in [Gennaro et. al. 2007](https://link.springer.com/article/10.1007/s00145-006-0347-3). As output of this ceremony, each party holds key share $k_i = f(i)$ where $f\in\mathbb{Z}_p[x]$ is a polynomial of degree $\tau-1$ such that $f(0)=k$.

The service operators publish the service public key $v=g_1^{k}$  and distribute it to clients. Additionally, the service operators publish $\{ v_1 \dots v_n \}$, the public keys for each $S_i$.

## POPRF Evaluation

Here we present the  end-to-end protocol for producing a verified POPRF computation, including the client $C$, a multi-party service $S$, and an untrusted relay $R$.

- $C$ computes $(st,req)\larr\text{POPRF.Req}(v,t,m)$
- $C$  computes $\pi\larr\text{Rel.Prove}(a,b,\frac{c}{r},d)$  where $(a,b)\larr req,\ (r,c,d)\larr st$
- $C$ sends $(t,req,\pi)$ to $R$
- $R$ sends $(t,req,\pi)$ to each $S_i$ for $i\in\{1 \dots n\}$
- $S_i$ checks $\text{Rel.Verify}(a,b,\pi)\stackrel{?}{=}1$. If not $S_i$ aborts
- $S_i$ computes $rep_i\larr\text{POPRF.BlindEv}(k_i,t,req)$
- $S_i$ sends $rep_i$ to $R$
- $R$ waits for $\tau$ responses $rep_i$
- $R$ computes $rep \larr \text{POPRF.Aggregate}(I,\{rep_i \mid i\in I\})$
- $R$ sends $rep$ to $C$
- $C$ computes $y\larr\text{POPRF.Finalize}(v,rep:st)$, aborting on failure.

## Performance

Computationally, this scheme is relatively expensive for both the client and the service, when compared to parings-free (P)OPRF protocols, because it requires use of pairings in the output calculation and operation on the output in $\mathbb{G}_T$ for share combination and verification.

# Alternatives

### Use an OPRF

The most obvious alternative is not to use a POPRF at all, and instead use an OPRF with authentication-based rate limiting.

The suitability of the current ODIS rate limiting function is discussed in [Domain Extension to ODIS (POPRF)](https://www.notion.so/Domain-Extension-to-ODIS-POPRF-55d743cdd7194a81b86d4c1863e73b6e), leading to the conclusion that this rate limiting function is not suitable.

As is done in [OPAQUE](https://datatracker.ietf.org/doc/draft-irtf-cfrg-opaque/), one option to adapting an OPRF for the use case of password hashing is to derive a tag-specific key. Given an OPRF function $F_k(m)$, the output given to the user is $F_{H(t||\hat{k})}(m)$ where $t$ is the tag and $\hat{k}$ is the services master secret. Unfortunately, this is not compatible with practical multi-party computation, and so cannot be used without changing the trust assumptions of ODIS. It also does not allow verifiability against a pre-shared public key.

### Pythia with NIZK-based Verifiability

In the [Pythia](https://www.notion.so/Pith-POPRF-Specification-493f1099460940f8a5d7dee4c78b4442) paper, verifiability is provided by a simple NIZK proof of same discrete log technique, similar to a Schnorr signature.

One way to make this amenable to threshold computation is to use an MPC protocol between signers, such as [FROST](https://crysp.uwaterloo.ca/software/frost/). This would require communication between the signers that does not currently exist, along with the engineering complexity of the implementation.

Another way would be to simply have each signer provide a proof against their own operator public key share $v_i$ and have the client verify all $\tau$ provided proofs. One challenge with this is that it would require the client to possess or receive the public key shares and identifiers $(v_i, a_i)$ for each signer. If they receive this in their software distribution, then a proactive key resharing would prevent the client from verifying the POPRF outputs until the receive a software update. Additionally, the client would need to receive the individual $y_i$ values from each party $S_i$ instead of only the combined $y$ value, and would need to compute the polynomial interpolation locally instead of allowing an untrusted relayer to do so and verifying the result. As a result the response size and amount of work required by the client, who is likely on a mobile device, would scale linearly with the number of service operators $n$. It may be possible to optimize this with techniques presented in [Zero-Knowledge Argument for Simultaneous Discrete Logarithms](https://github.com/gtank/celo-research/blob/master/account-recovery/Chow%2C), but that has not been investigated.

### Jarecki-Krawcyk-Resch DH POPRF

In [Threshold Partially-Oblivious PRFs with Applications to Key Management](http://ia.cr/2018/733), the authors present a threshold and verifiable POPRF without the use of pairings. Verification is provided by an interactive protocol, from which the verification procedure above is derived. This protocol avoids the use of pairing and so enjoys much higher performance when the number of parties involved is small. One drawback of the design is that verification happens against a tag-specific public key instead of a single public key which can be pre-shared to clients. Another challenge is that is unclear how to produce and distribute the required keys to each party without a trusted dealer.

### 3HashSDHI POPRF

In [A Fast and Simple Partially Oblivious PRF, with Applications](https://ia.cr/2021/864), the authors describe a verifiable POPRF based on the Dodis-Yampolskiy PRF. This construction does not need pairings. It's verification used a similar NIZK technique as proposed for Pythia. It is not clear if the 3HashSDHI scheme can be thesholdized in an efficient manner. If it can, then it meets all requirements without the need of pairings, allowing for better computational efficiency. Assuming thresholdization is possible, similar techniques can be used [as described with reference to Pythia](https://www.notion.so/Pith-POPRF-Specification-493f1099460940f8a5d7dee4c78b4442) to make the threshold result verifiable, but without computation in the target group.