import { For } from 'solid-js';

type Tier = {
  name: string;
  where: string;
  evidence: string;
  blast: string;
};

/**
 * The framing section: an org deploys agents across five kinds of machines,
 * and the difference between them is how much evidence a mint can demand,
 * not which product you buy.
 */
const TIERS: Tier[] = [
  {
    name: 'Unmanaged laptops',
    where: 'Contractors, interns, BYOD. No hardware you can rely on.',
    evidence: 'Software witness, per-source budgets, short expiry.',
    blast: 'One single-use pass, probably already spent.',
  },
  {
    name: 'Hardware-backed laptops',
    where: 'Admins, release engineers, executives. TPM or secure enclave present.',
    evidence: 'Holder keys in hardware; device attestation checked at mint.',
    blast: 'A pass bound to a key that never left the machine.',
  },
  {
    name: 'Ephemeral cloud',
    where: 'CI runners, scrapers, batch jobs.',
    evidence: 'Workload identity, one token per action, budget per job.',
    blast: 'A burst that hits its budget cap and stops.',
  },
  {
    name: 'Confidential cloud',
    where: 'Services near money or customer data.',
    evidence: 'SEV-SNP / TDX quotes as mint inputs; policy names allowed measurements and signers.',
    blast: 'An attacker has to be the measured workload first.',
  },
  {
    name: 'Critical, bare metal',
    where: 'The minting service itself and its root keys.',
    evidence: 'TamaGo in a TEE: no Linux, libc, or shell. The measurement covers the whole binary.',
    blast: 'No shell to pop. Rotate one key.',
  },
];

export function DeployTiers() {
  return (
    <section class="section" id="deployments">
      <div class="section-head">
        <p class="section-path" aria-hidden="true">tamayo/deployments</p>
        <h2>From metal to Mattermost,<br />from the TEE to TikTok</h2>
        <p>
          An agent rollout never lands on one kind of machine. The same quarter puts agents on an
          intern's unmanaged laptop and next to the payment service. You don't want five security
          products for that. Tamayo covers all five tiers with one policy language; what changes
          between tiers is how much evidence a mint demands.
        </p>
      </div>

      <div class="hw-table-wrap t-stagger">
        <table class="hw-table bb tier-table">
          <caption class="sr-only">Deployment tiers, evidence requirements, and credential impact</caption>
          <thead>
            <tr>
              <th>Tier</th>
              <th>Where agents run</th>
              <th>Evidence policy can demand</th>
              <th>What a stolen credential costs</th>
            </tr>
          </thead>
          <tbody>
            <For each={TIERS}>
              {(tier) => (
                <tr>
                  <td data-label="Tier"><b>{tier.name}</b></td>
                  <td data-label="Where agents run">{tier.where}</td>
                  <td data-label="Evidence policy can demand">{tier.evidence}</td>
                  <td data-label="Stolen credential cost">{tier.blast}</td>
                </tr>
              )}
            </For>
          </tbody>
        </table>
      </div>

      <div class="primitive-notes t-stagger" style={{ 'margin-top': '18px' }}>
        <article class="primitive-note bb-pulse t-card-resize">
          <h3>The same packages at every tier</h3>
          <p>
            <code>tokenauth</code>, <code>tokenservice</code>, and the crypto underneath are
            cgo-free Go. The same build runs on the intern's laptop and inside the enclave. Only
            the policy file changes.
          </p>
        </article>
        <article class="primitive-note bb-pulse t-card-resize">
          <h3>Weak policies fail the build</h3>
          <p>
            A production policy that accepts dev-grade evidence, or leaves a rate-limit bucket up
            to the caller, fails at <code>tokenauth.Compile</code>. Tier decisions live in one
            reviewable file instead of scattered per-service code.
          </p>
        </article>
      </div>
    </section>
  );
}
