const OPA = 'https://www.openpolicyagent.org/';
const CEDAR = 'https://www.cedarpolicy.com/';
const SPIFFE = 'https://spiffe.io/';

export function InteropSection() {
  return (
    <section class="section" id="interop">
      <div class="section-head">
        <p class="section-path" aria-hidden="true">tamayo/interop</p>
        <h2>Plugs into the stack you already run</h2>
        <p class="section-sub">Login, gateways, and request-time policy all stay where they are</p>
        <p>
          Most companies already have an identity provider, an API gateway, and a policy engine.
          Tamayo replaces none of them. It adds the one decision none of them make: whether a
          credential should exist at all.
        </p>
      </div>

      <div class="principles t-stagger">
        <div class="principle bb-line t-card-resize">
          <b>Your identity provider stays</b>
          <p>
            Okta, Entra ID, or Google Workspace keep doing login. The session or OIDC token they
            produce is how a caller reaches the mint endpoint in the first place — tamayo never
            sees a password and doesn't want to. It decides what an already-authenticated caller
            may mint, not who they are.
          </p>
        </div>
        <div class="principle bb-line t-card-resize">
          <b>Your gateway stays</b>
          <p>
            Verification is a stateless check: one call to <code>/v1/verify/*</code>, or the Go
            package embedded directly in your middleware — next to the JWT filter you already run
            in Envoy, Kong, nginx, or plain <code>net/http</code>. The SigBird gateway in the case
            study below does exactly this in production.
          </p>
        </div>
        <div class="principle bb-line t-card-resize">
          <b>Your policy engine stays</b>
          <p>
            <a href={OPA} target="_blank" rel="noreferrer">OPA</a> and{' '}
            <a href={CEDAR} target="_blank" rel="noreferrer">Cedar</a> answer "may this request
            proceed" every time a request arrives. <code>tokenauth</code> answers "may this
            credential exist" once, at mint time. They compose: request-time rules keep running at
            the edge, and the mint decision sits in front of the credentials agents spend.
          </p>
        </div>
      </div>

      <div class="primitive-notes t-stagger" style={{ 'margin-top': '14px' }}>
        <article class="primitive-note bb-pulse t-card-resize">
          <h3>Workload identity is evidence, not competition</h3>
          <p>
            If you run <a href={SPIFFE} target="_blank" rel="noreferrer">SPIFFE</a>, mTLS meshes,
            or attested workloads, that machinery feeds straight in: TPM, TEE, and keystore
            attestations are gate inputs the policy checks before minting
            (<code>"allowed_gates": ["tee"]</code>).
          </p>
        </article>
        <article class="primitive-note bb-pulse t-card-resize">
          <h3>Adopt one action at a time</h3>
          <p>
            No big-bang migration. Pick one privileged action — a payment, an upload, a send — and
            require a pass for it. Bearer tokens keep working everywhere else while the blast
            radius shrinks one endpoint at a time.
          </p>
        </article>
      </div>
    </section>
  );
}
