const NIST_R3 = 'https://csrc.nist.gov/Projects/pqc-dig-sig/round-3-additional-signatures';
const FIPS_204 = 'https://csrc.nist.gov/pubs/fips/204/final';
const POMFRIT_PAPER = 'https://eprint.iacr.org/2026/109';
const GH = 'https://github.com/maceip/tamayo/tree/main';

export function StaticSections() {
  return (
    <section class="section dark" id="stack">
      <div class="section-head">
        <h2>Under the hood</h2>
        <p>
          The mint path is small enough to measure. Policy compiles to a yes/no before any token
          exists, issuance is blind so the issuer can't recognize its own tokens later, and the
          signatures are post-quantum, in pure Go, from phone apps down to firmware.
        </p>
      </div>

      <div class="principles">
        <div class="principle bb-line t-card-resize">
          <b>Bare-metal Go</b>
          <p>
            TamaGo runs Go as firmware with no Linux, libc, or shell in the critical path. The
            same cgo-free packages cross-build for <code>GOOS=tamago</code> on amd64, arm, arm64,
            and riscv64 — USB armory, i.MX8M Plus, QEMU sifive_u, and microVMs like Firecracker.
          </p>
        </div>
        <div class="principle bb-line t-card-resize">
          <b>Attestation as a policy input</b>
          <p>
            Android Keystore, laptop TPMs, SGX, SEV-SNP, TDX, and TamaGo all answer the same
            question: is this request coming from an approved execution environment?{' '}
            <code>tokenauth</code> takes code identity, signer, and version as inputs before it
            mints anything.
          </p>
        </div>
        <div class="principle bb-line t-card-resize">
          <b>Blind issuance</b>
          <p>
            Issuance runs the PoMFRIT one-more-MAYO blind path (<code>sign_1</code> →{' '}
            <code>sign_2</code> → <code>sign_3</code> → verify). The issuer approves a blinded
            request and never sees the finished token, so presenting one later reveals nothing
            about who minted it. Evidence stays at mint time; none of it travels with the token.
          </p>
        </div>
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
        <p class="hw-footnote">
          Correctness: FAEST against official KATs, MAYO against NIST round-2 KATs (100/100 at
          L1/L3/L5), PoMFRIT byte-exact against the C++/C reference including on-device riscv64,
          ML-DSA against NIST ACVP vectors. <code>go get github.com/maceip/tamayo</code> to use
          any package alone.
        </p>
      </div>
    </section>
  );
}

export function PolicySection() {
  return (
    <section class="section" id="policy">
      <div class="section-head">
        <h2>The policy file is the security review</h2>
        <p>
          <code>tokenauth</code> compiles JSON policy into a mint decision: which evidence is
          enough before a pass exists. One file states what every tier accepts, so the review
          happens where the decision is made. The verifier receives the pass, never the policy.
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
            Mint this token family, for this purpose, under these limits — or deny. Your app
            supplies transport and storage; Tamayo makes the mint decision.
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
        <h2>Agents spend credentials at machine speed</h2>
        <p>
          Software that browses, remembers, calls tools, and runs code. A session cookie is the
          wrong credential for that — each privileged action needs its own narrow pass.
        </p>
      </div>

      <div class="agent-stats t-stagger" aria-label="Agent traffic context">
        <article class="agent-stat bb-pulse t-card-resize">
          <b>57.5%</b>
          <strong>of HTML requests are automated</strong>
          <span>
            Cloudflare Radar (June 2026): bots at 57.5% vs humans at 42.5% of HTML traffic — the
            first time machines were the majority on that measure.
          </span>
        </article>
        <article class="agent-stat bb-pulse t-card-resize">
          <b>~1,000×</b>
          <strong>more sites per task</strong>
          <span>
            For the same shopping task, a person might visit ~5 sites; an agent has been described
            as hitting ~5,000 (Cloudflare CEO, SXSW 2026).
          </span>
        </article>
      </div>

      <div class="principles" style={{ 'margin-top': '18px' }}>
        <div class="principle bb-line t-card-resize">
          <b>Memory</b>
          <p>
            Agents keep context across steps: pages, goals, credentials, intermediate results. A
            token limits what that stored context can authorize.
          </p>
        </div>
        <div class="principle bb-line t-card-resize">
          <b>Tool calls</b>
          <p>
            APIs, browsers, calendars, payments. Each call is a privileged action and should carry
            its own token instead of borrowing full account access.
          </p>
        </div>
        <div class="principle bb-line t-card-resize">
          <b>Code generation</b>
          <p>
            Agents write scripts and workflows on the fly. What matters is whether the resulting
            action stays inside what was approved, not whether a human typed it.
          </p>
        </div>
      </div>

      <div class="primitive-notes t-stagger" style={{ 'margin-top': '14px' }}>
        <article class="primitive-note bb-pulse t-card-resize">
          <h3>Code execution</h3>
          <p>
            Generated code runs in sandboxes, CI, cloud functions, or on-device, and its side
            effects are real: money moves, messages send. Require a token before the action, not
            after.
          </p>
        </article>
        <article class="primitive-note bb-pulse t-card-resize">
          <h3>Above policy</h3>
          <p>
            Policy decides what gets minted; agents then spend it at machine speed. Nothing in the
            stack assumes a person behind a browser anymore.
          </p>
        </article>
      </div>
    </section>
  );
}
