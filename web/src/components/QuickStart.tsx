const RELEASES = 'https://github.com/maceip/tamayo/releases';
const PKG_DOCS = 'https://pkg.go.dev/github.com/maceip/tamayo';

export function QuickStart() {
  return (
    <section class="section" id="quickstart">
      <div class="section-head">
        <h2>Quick start</h2>
        <p class="section-sub">A working issuer in five commands</p>
        <p>
          One static binary, pure Go, no cgo. Every push to main cuts a{' '}
          <a href={RELEASES} target="_blank" rel="noreferrer">release</a> that runs a full blind
          mint-and-verify loop on a native runner before it ships.
        </p>
      </div>

      <div class="qs-grid t-stagger">
        <article class="pol-panel bb qs-step">
          <h3 class="pol-title"><span class="qs-num">1</span>Install</h3>
          <pre class="pol-code"><code>{'go install github.com/maceip/tamayo/cmd/tamayo@latest'}</code></pre>
          <p class="qs-note">
            Or grab a prebuilt archive from the releases page — linux, macOS, and Windows, with
            SHA256SUMS.
          </p>
        </article>

        <article class="pol-panel bb qs-step">
          <h3 class="pol-title"><span class="qs-num">2</span>Mint and verify a token</h3>
          <pre class="pol-code"><code>{'tamayo keygen -out issuer.json\ntamayo mint-burn -issuer issuer.json \\\n  -challenge "origin challenge" -out token.b64\ntamayo verify-burn -issuer issuer.json \\\n  -token token.b64 -challenge "origin challenge"'}</code></pre>
          <p class="qs-note">
            <code>tamayo demo -issuer issuer.json</code> runs the whole burn and private-identity
            loop end to end and prints <code>RESULT: PASS</code>.
          </p>
        </article>

        <article class="pol-panel bb qs-step">
          <h3 class="pol-title"><span class="qs-num">3</span>Put a policy in front of it</h3>
          <pre class="pol-code"><code>{'tamayo example-policy > policy.json\ntamayo serve -issuer issuer.json \\\n  -policy policy.json   # 127.0.0.1:8787'}</code></pre>
          <p class="qs-note">
            <code>serve</code> exposes <code>/v1/blind-sign</code> (policy and budget gated) and{' '}
            <code>/v1/verify/*</code> (replay-checked). The policy file is the one described in{' '}
            <a href="#policy">the section above</a> — weak evidence fails to compile.
          </p>
        </article>
      </div>

      <p class="qs-library">
        Using it as a library instead? <code>go get github.com/maceip/tamayo@latest</code> — plain
        Go modules, docs on <a href={PKG_DOCS} target="_blank" rel="noreferrer">pkg.go.dev</a>.
      </p>
    </section>
  );
}
