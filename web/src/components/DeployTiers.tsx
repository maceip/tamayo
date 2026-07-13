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
    name: 'Laptops that don\u2019t matter',
    where: 'Contractors, interns, BYOD. No hardware you can rely on.',
    evidence: 'Software witness, per-source budgets, short expiry.',
    blast: 'One single-use pass, probably already spent.',
  },
  {
    name: 'Laptops that do matter',
    where: 'Admins, release engineers, executives. TPM or secure enclave present.',
    evidence: 'Holder keys in hardware; device attestation checked at mint.',
    blast: 'A pass bound to a key that never left the machine.',
  },
  {
    name: 'Cloud that doesn\u2019t matter',
    where: 'CI runners, scrapers, batch jobs.',
    evidence: 'Workload identity, one token per action, budget per job.',
    blast: 'A burst that hits its budget cap and stops.',
  },
  {
    name: 'Cloud that does matter',
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
        <h2>Five tiers, one policy</h2>
        <p>
          An agent rollout never lands on one kind of machine. The same quarter puts agents on an
          intern's unmanaged laptop and next to the payment service. You don't want five security
          products for that. Tamayo is one policy language where the tiers differ only in the
          evidence a mint demands.
        </p>
      </div>

      <div class="hw-table-wrap t-stagger">
        <table class="hw-table bb tier-table">
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
                  <td><b>{tier.name}</b></td>
                  <td>{tier.where}</td>
                  <td>{tier.evidence}</td>
                  <td>{tier.blast}</td>
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
            cgo-free Go. The build that runs on the intern's laptop is the build that runs inside
            the enclave; only the policy file changes.
          </p>
        </article>
        <article class="primitive-note bb-pulse t-card-resize">
          <h3>Downgrades are compile errors</h3>
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
