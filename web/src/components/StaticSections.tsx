import { For } from 'solid-js';
import { RUNTIME_COLUMNS } from '../data/runtimeStacks';
import { RuntimeStackIcon } from './RuntimeStackIcons';

const NIST_R3 = 'https://csrc.nist.gov/Projects/pqc-dig-sig/round-3-additional-signatures';
const FIPS_204 = 'https://csrc.nist.gov/pubs/fips/204/final';
const POMFRIT_PAPER = 'https://eprint.iacr.org/2026/109';
const GH = 'https://github.com/maceip/tamayo/tree/main';

const TAMAGO_TARGETS = [
  { arch: 'arm', board: 'USB armory Mk II', detail: 'NXP i.MX6UL / i.MX6ULZ' },
  { arch: 'arm', board: 'MCIMX6ULL-EVK', detail: 'NXP i.MX6ULL evaluation kit' },
  { arch: 'arm64', board: '8MPLUSLPD4-EVK', detail: 'NXP i.MX8M Plus' },
  { arch: 'riscv64', board: 'QEMU sifive_u', detail: 'SiFive FU540 — Tamayo on-device demo' },
  { arch: 'amd64', board: 'Cloud Hypervisor / QEMU microvm / Firecracker', detail: 'bare-metal Go in microVMs' },
];

export function StaticSections() {
  return (
    <>
      <section class="section" id="tamago">
        <div class="section-head">
          <h2>OSI Layer 1: TamaGo</h2>
          <p>
            TamaGo runs Go as firmware — no Linux, libc, or shell in the critical path. Tamayo’s
            crypto is cgo-free and cross-builds for <code>GOOS=tamago</code> on amd64, arm, arm64,
            and riscv64, so the issuer measures a small program, not an app buried in an OS.
          </p>
        </div>

        <div class="hw-table-wrap t-stagger">
          <table class="hw-table bb">
            <thead>
              <tr>
                <th>Arch</th>
                <th>Board / target</th>
                <th>Notes</th>
              </tr>
            </thead>
            <tbody>
              <For each={TAMAGO_TARGETS}>
                {(row) => (
                  <tr>
                    <td><code>{row.arch}</code></td>
                    <td><b>{row.board}</b></td>
                    <td>{row.detail}</td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
          <p class="hw-footnote">
            On-device check: <code>cmd/qemudemo</code> boots the PoMFRIT blind loop on QEMU sifive_u
            (riscv64) and verifies L1+L3+L5 byte-exact against reference vectors.
          </p>
        </div>

        <div class="primitive-notes t-stagger" style={{ 'margin-top': '18px' }}>
          <article class="primitive-note bb-pulse t-card-resize">
            <h3>Same packages, two GOOS values</h3>
            <p>
              Develop under host Go. Deploy under <code>GOOS=tamago</code> with the TamaGo toolchain
              when the job needs bare metal. Library packages stay cgo-free either way.
            </p>
          </article>
          <article class="primitive-note bb-pulse t-card-resize">
            <h3>A shorter measurement path</h3>
            <p>
              Policy can bind to a known runtime measurement of the minting binary — source to
              allowed program — without trusting a full userspace image.
            </p>
          </article>
        </div>
      </section>

      <section class="section dark" id="tee">
        <div class="section-head">
          <h2>OSI Layer 2: Trusted Execution Environments, Confidential VMs, and Secure Enclaves</h2>
          <p>
            Tamayo grew out of remote attestation work, where the hard part is deciding which
            measured program, signer, configuration, and update path may act for a user. Those
            fields feed <code>tokenauth</code> before a pass is minted.
          </p>
        </div>
        <div class="principles">
          <div class="principle bb-line t-card-resize">
            <b>What attestation proves</b>
            <p>
              A TEE or confidential VM reports a measurement of the running code. Tamayo treats that
              as a policy input — not a substitute for signatures, blind issuance, or verifier checks.
            </p>
          </div>
          <div class="principle bb-line t-card-resize">
            <b>Fields that matter</b>
            <p>
              Code identity, signer, version, and data path stay explicit so an issuer can accept one
              runtime and reject another. The same language covers enclaves and CVMs.
            </p>
          </div>
          <div class="principle bb-line t-card-resize">
            <b>Evidence sources</b>
            <p>
              Android Keystore / attestation, laptop TPM or hardware keys, Intel SGX, AMD SEV-SNP,
              Intel TDX, and bare-metal TamaGo all answer the same question: is this request from an
              approved execution environment for this token family?
            </p>
          </div>
        </div>
      </section>

      <section class="section" id="primitives">
        <div class="section-head">
          <h2>OSI Layer 3: Cryptography</h2>
          <p>
            Passes that authorize spend can outlive classical signature assumptions. Tamayo’s
            signing stack is post-quantum where it matters: NIST additional-signature candidates
            plus FIPS 204 ML-DSA — pure Go, no cgo.
          </p>
        </div>

        <div class="crypto-provenance t-stagger">
          <article class="primitive-note bb-pulse t-card-resize">
            <h3>Where it came from</h3>
            <p>
              FAEST is a RUST→GO port of <code>ait-crypto/faest-rs</code>. MAYO follows pq-mayo /
              MAYO-C. PoMFRIT follows the One-More-MAYO paper and reference dumpers. ML-DSA is
              written from FIPS 204. SHA-3 and AES stay in Go’s stdlib.
            </p>
          </article>
          <article class="primitive-note bb-pulse t-card-resize">
            <h3>How we know it matches</h3>
            <p>
              FAEST: official KATs. MAYO: NIST round-2 KATs (100/100 at L1/L3/L5). PoMFRIT:
              byte-exact vs the C++/C reference, including on-device sifive_u. ML-DSA: NIST ACVP
              vectors, byte-exact.
            </p>
          </article>
          <article class="primitive-note bb-pulse t-card-resize">
            <h3>Use a package alone</h3>
            <p>
              <code>go get github.com/maceip/tamayo</code> — import <code>faest</code>,{' '}
              <code>mayo</code>, <code>pomfrit</code>, or <code>mldsa</code> without the token stack.
              Host Go for normal builds; TamaGo only when targeting bare metal.
            </p>
          </article>
        </div>

        <div class="primitive-panel t-stagger" style={{ 'margin-top': '18px' }}>
          <table class="primitive-table bb">
            <thead>
              <tr><th>Primitive</th><th>What it is</th><th>Standalone use</th><th>Status</th></tr>
            </thead>
            <tbody>
              <tr>
                <td>
                  <b>
                    <a href={`${GH}/faest`} target="_blank" rel="noreferrer">FAEST</a>
                  </b>
                </td>
                <td>PQ signature from symmetric primitives + VOLE-in-the-head proofs.</td>
                <td>Sign runtime statements, policy files, or transparency-log heads.</td>
                <td>
                  <a href={NIST_R3} target="_blank" rel="noreferrer">
                    NIST additional-signature round 3
                  </a>
                </td>
              </tr>
              <tr>
                <td>
                  <b>
                    <a href={`${GH}/mayo`} target="_blank" rel="noreferrer">MAYO</a>
                  </b>
                </td>
                <td>Compact multivariate signature over GF(16).</td>
                <td>Direct signing, or the preimage path inside blind signatures.</td>
                <td>
                  <a href={NIST_R3} target="_blank" rel="noreferrer">
                    NIST additional-signature round 3
                  </a>
                </td>
              </tr>
              <tr>
                <td>
                  <b>
                    <a href={`${GH}/pomfrit`} target="_blank" rel="noreferrer">PoMFRIT</a>
                  </b>
                </td>
                <td>One-More-MAYO blind signature with verifier checks.</td>
                <td>Anonymous one-use credentials and blind issuance.</td>
                <td>
                  <a href={POMFRIT_PAPER} target="_blank" rel="noreferrer">
                    ePrint 2026/109
                  </a>
                </td>
              </tr>
              <tr>
                <td>
                  <b>
                    <a href={`${GH}/mldsa`} target="_blank" rel="noreferrer">ML-DSA</a>
                  </b>
                </td>
                <td>Module-lattice signature (Dilithium) for FIPS-track use.</td>
                <td>Holder proofs and PQ email-token profiles.</td>
                <td>
                  <a href={FIPS_204} target="_blank" rel="noreferrer">
                    FIPS 204
                  </a>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section class="section" id="runtime">
        <div class="section-head">
          <h2>Runs Everywhere</h2>
          <p>
            OSI Layer 4 — transport. The same cgo-free packages compose on phones, laptops, cloud
            TEEs, and bare metal. Product code owns HTTP, storage, and UI; Tamayo owns crypto and
            mint/verify.
          </p>
        </div>
        <div class="runtime-legend" aria-hidden="true">
          <span class="runtime-kind build">we build</span>
          <span class="runtime-kind require">we require</span>
          <span class="runtime-kind config">we configure</span>
        </div>
        <div class="runtime-model t-stagger" aria-label="Runtime stack comparison">
          <For each={RUNTIME_COLUMNS}>
            {(column) => (
              <article class={`runtime-card bb-pulse t-card-resize ${column.tone}`}>
                <h3>{column.title}</h3>
                <ul class="runtime-stack">
                  <For each={column.items}>
                    {(item) => (
                      <li class={`runtime-layer kind-${item.kind ?? 'build'}`}>
                        <span class="runtime-ico-wrap">
                          <RuntimeStackIcon name={item.icon} />
                        </span>
                        <div class="runtime-layer-copy">
                          {item.href ? (
                            <a href={item.href} target="_blank" rel="noreferrer">
                              {item.label}
                            </a>
                          ) : (
                            <b>{item.label}</b>
                          )}
                          <span>{item.detail}</span>
                        </div>
                      </li>
                    )}
                  </For>
                </ul>
              </article>
            )}
          </For>
        </div>
      </section>

      <section class="section dark" id="session">
        <div class="section-head">
          <h2>OSI Layer 5: Issuance session</h2>
          <p>
            A password or broad OAuth grant is the wrong shape for an agent. Issuance runs the
            PoMFRIT one-more-MAYO blind path (<code>sign_1</code> → <code>sign_2</code> →{' '}
            <code>sign_3</code> → verify), so the holder gets a narrow pass without a permanent
            account handle.
          </p>
        </div>
        <div class="principles">
          <div class="principle bb-line t-card-resize">
            <b>Blind issuance</b>
            <p>
              The issuer approves a blinded preimage request and never sees the final showable pass.
              Later presentations do not become receipts back to the issuer.
            </p>
          </div>
          <div class="principle bb-line t-card-resize">
            <b>Narrow disclosure</b>
            <p>
              The holder proves the pass is valid without dumping email proofs, runtime measurements,
              or other mint-time evidence into the verifier.
            </p>
          </div>
          <div class="principle bb-line t-card-resize">
            <b>Evidence stays in-session</b>
            <p>
              Email proofs and measurements inform <code>tokenauth</code> at mint time. They do not
              have to ride along as a new identity on every later request.
            </p>
          </div>
        </div>
      </section>
    </>
  );
}

export function PolicySection() {
  return (
    <section class="section" id="policy">
      <div class="section-head">
        <h2>OSI Layer 7: Policy</h2>
        <p>
          <code>tokenauth</code> compiles JSON policy into a mint decision: which evidence is
          enough before a pass exists. The verifier receives the pass — never the policy file.
        </p>
      </div>
      <div class="primitive-notes t-stagger">
        <article class="primitive-note bb-pulse t-card-resize">
          <h3>Inputs</h3>
          <p>
            Token family, origin, email / address proof, runtime measurement, signer identity,
            assurance level, and per-user or per-bucket budgets (reserve / deny / rollover).
          </p>
        </article>
        <article class="primitive-note bb-pulse t-card-resize">
          <h3>Output</h3>
          <p>
            Mint this token family, for this purpose, under these limits — or deny. Product code
            supplies transport and durable stores; Tamayo owns the decision boundary.
          </p>
        </article>
      </div>
    </section>
  );
}

export function AgentsSection() {
  return (
    <section class="section dark" id="agents">
      <div class="section-head">
        <h2>OSI Layer 8: Agents</h2>
        <p>
          Software that browses, remembers, calls tools, and runs code. A session cookie is the
          wrong credential — agents need a narrow pass per privileged action.
        </p>
      </div>

      <div class="agent-stats t-stagger" aria-label="Agent traffic context">
        <article class="agent-stat bb-pulse t-card-resize">
          <b>57.5%</b>
          <strong>of HTML requests are automated</strong>
          <span>
            Cloudflare Radar (June 2026): bots at 57.5% vs humans at 42.5% of HTML traffic — the first
            machine majority on that measure.
          </span>
        </article>
        <article class="agent-stat bb-pulse t-card-resize">
          <b>~1,000×</b>
          <strong>more sites per task</strong>
          <span>
            Same shopping intent: a person might hit ~5 sites; an agent doing the job has been described
            as hitting ~5,000 (Cloudflare CEO, SXSW 2026). Not a flat “10× web” — a different request shape.
          </span>
        </article>
      </div>

      <div class="principles" style={{ 'margin-top': '18px' }}>
        <div class="principle bb-line t-card-resize">
          <b>Memory</b>
          <p>
            Durable context across steps — pages, goals, credentials, intermediate results. A pass
            bounds what that memory may authorize; it is not a fresh human session each click.
          </p>
        </div>
        <div class="principle bb-line t-card-resize">
          <b>Tool calls</b>
          <p>
            APIs, browsers, calendars, payment rails — each call is a privileged action that needs
            its own narrow pass, not ambient account access.
          </p>
        </div>
        <div class="principle bb-line t-card-resize">
          <b>Code generation</b>
          <p>
            Scripts and workflows synthesized on the fly. The check is whether the generated action
            stays inside the approved purpose — not whether a human typed it.
          </p>
        </div>
      </div>

      <div class="primitive-notes t-stagger" style={{ 'margin-top': '14px' }}>
        <article class="primitive-note bb-pulse t-card-resize">
          <h3>Code execution</h3>
          <p>
            Generated code runs in sandboxes, CI, cloud functions, or on-device. That is where
            traffic and tools become irreversible side effects — present a pass before acting.
          </p>
        </article>
        <article class="primitive-note bb-pulse t-card-resize">
          <h3>Above policy</h3>
          <p>
            Policy decides what may be minted. Agents spend that mint at machine speed. The principal
            is no longer assumed to be a person behind a browser.
          </p>
        </article>
      </div>
    </section>
  );
}
