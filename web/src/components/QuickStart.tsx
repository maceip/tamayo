const RELEASES = 'https://github.com/maceip/tamayo/releases';
const PKG_DOCS = 'https://pkg.go.dev/github.com/maceip/tamayo';
const MAILPROOF = 'https://github.com/maceip/tamayo/tree/main/examples/mailproof';
const ISSUERD = 'https://github.com/maceip/tamayo/tree/main/services/issuerd';

export function QuickStart() {
  return (
    <section class="section" id="quickstart">
      <div class="section-head">
        <p class="section-path" aria-hidden="true">tamayo/quickstart</p>
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

      <div class="mailproof t-stagger">
        <div class="mailproof-copy">
          <p class="mailproof-kicker">Optional path</p>
          <h3>Zero-signup enrollment over email</h3>
          <p>
            Your app can hand out tokens without creating a single account. The user proves they
            control a mailbox once — by sending one email to the issuer, or by typing back a
            6-digit code — and their device mints a reusable private-identity token. The service
            they spend it at never learns the address, and the issuer keeps only a salted hash of
            it for rate limiting.
          </p>
          <pre class="pol-code"><code>{'cd examples/mailproof\ndocker compose up --build   # issuer + demo image host\ncd android && ./gradlew :demo:assembleDebug'}</code></pre>
          <p class="qs-note">
            The <a href={MAILPROOF} target="_blank" rel="noreferrer">reference package</a> is three
            small pieces: <a href={ISSUERD} target="_blank" rel="noreferrer"><code>issuerd</code></a>,
            an issuer that accepts verification mail through an embedded SMTP listener, an MTA pipe,
            or a webhook; an anonymous image host that verifies tokens with the issuer's public key
            and never contacts it again; and an Android <code>enroll</code> library whose Compose
            overlay — the mocked screen shown here — runs the whole flow. Verification mail sent from the
            user's own app stays in their Sent folder, so they can always see exactly what was
            disclosed.
          </p>
        </div>

        <figure class="mailproof-mock" aria-label="Mocked screenshot of the Android enrollment overlay">
          <div class="phone-mock">
            <div class="phone-screen">
              <div class="phone-statusbar">
                <span>9:41</span>
                <span class="phone-cam" />
                <span>▲ ▮</span>
              </div>
              <div class="phone-app">
                <p class="phone-app-title">Mailproof demo</p>
                <p class="phone-app-line">No token yet.</p>
                <div class="phone-app-btn">Get a token</div>
                <div class="phone-app-btn dim">Upload an image with it</div>
              </div>
              <div class="phone-scrim">
                <div class="enroll-card">
                  <p class="enroll-title">Get a token — no signup</p>
                  <p class="enroll-body">
                    Prove you control a mailbox and this device mints an anonymous, reusable pass.
                    The service you use it at never learns your address.
                  </p>
                  <div class="enroll-btn filled">Send a verification email</div>
                  <div class="enroll-btn outlined">Email me a code instead</div>
                  <div class="enroll-btn text">Not now</div>
                </div>
              </div>
            </div>
          </div>
          <figcaption>
            Mocked screenshot — the <code>EnrollOverlay</code> from the Android enroll library.
          </figcaption>
        </figure>
      </div>
    </section>
  );
}
