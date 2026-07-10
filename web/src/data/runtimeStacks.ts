export type RuntimeStackItem = {
  icon: 'app' | 'api' | 'policy' | 'mail' | 'key' | 'crypto' | 'issuer' | 'burn' | 'tpm' | 'cloud' | 'shield' | 'log' | 'tee' | 'board' | 'kernel' | 'store';
  label: string;
  detail: string;
  href?: string;
  kind?: 'build' | 'require' | 'config';
};

export type RuntimeColumn = {
  id: string;
  title: string;
  tone: 'android' | 'laptop' | 'cloud' | 'baremetal';
  items: RuntimeStackItem[];
};

const GH = 'https://github.com/maceip/tamayo/blob/main';

export const RUNTIME_COLUMNS: RuntimeColumn[] = [
  {
    id: 'android',
    title: 'Android phone',
    tone: 'android',
    items: [
      {
        icon: 'app',
        label: 'Product app',
        detail: 'Transport, storage, and UI stay with the product.',
        kind: 'config',
      },
      {
        icon: 'api',
        label: 'tokenservice',
        detail: 'Issuer / verifier API surface.',
        href: `${GH}/tokenservice/service.go`,
        kind: 'build',
      },
      {
        icon: 'policy',
        label: 'tokenauth',
        detail: 'Policy gate before a pass is minted.',
        href: `${GH}/tokenauth/types.go`,
        kind: 'build',
      },
      {
        icon: 'mail',
        label: 'EVT rail',
        detail: 'Browser-mediated Google EVT email proof.',
        href: `${GH}/emailtoken/evt.go`,
        kind: 'build',
      },
      {
        icon: 'key',
        label: 'Android Keystore',
        detail: 'Attestation evidence for authorization.',
        kind: 'require',
      },
      {
        icon: 'crypto',
        label: 'FAEST · MAYO · ML-DSA',
        detail: 'Same cgo-free crypto packages as every other column.',
        kind: 'build',
      },
    ],
  },
  {
    id: 'laptop',
    title: 'Windows laptop',
    tone: 'laptop',
    items: [
      {
        icon: 'app',
        label: 'Desktop / browser',
        detail: 'Product shell presents the pass; Tamayo owns the crypto.',
        kind: 'config',
      },
      {
        icon: 'issuer',
        label: 'cmd/tamayo',
        detail: 'Reference issuer shows the contract, not the product UI.',
        href: `${GH}/cmd/tamayo/serve.go`,
        kind: 'build',
      },
      {
        icon: 'key',
        label: 'Holder proof',
        detail: 'Ed25519, FAEST-128s, or ML-DSA-44 bind a presentation.',
        href: `${GH}/tokenprofile/private_identity.go`,
        kind: 'build',
      },
      {
        icon: 'burn',
        label: 'Burn credential',
        detail: 'One request without a stable user handle.',
        href: `${GH}/tokenprofile/burn.go`,
        kind: 'build',
      },
      {
        icon: 'tpm',
        label: 'TPM / hardware keys',
        detail: 'Optional device-bound evidence when policy asks for it.',
        kind: 'require',
      },
      {
        icon: 'crypto',
        label: 'Host Go (windows/amd64)',
        detail: 'Stock toolchain; cgo on or off.',
        kind: 'config',
      },
    ],
  },
  {
    id: 'cloud',
    title: 'Cloud with TEE',
    tone: 'cloud',
    items: [
      {
        icon: 'cloud',
        label: 'Issuer deployment',
        detail: 'HTTP, durable stores, and ops stay outside the library.',
        kind: 'config',
      },
      {
        icon: 'log',
        label: 'Key transparency',
        detail: 'Clients can detect issuer key history changes.',
        href: `${GH}/transparency/transparency.go`,
        kind: 'build',
      },
      {
        icon: 'policy',
        label: 'Measurement auth',
        detail: 'TEE claims become inputs to the mint decision.',
        href: `${GH}/tokenauth/evaluate.go`,
        kind: 'build',
      },
      {
        icon: 'tee',
        label: 'SGX · SEV-SNP · TDX',
        detail: 'Attested runtimes feed the same policy language.',
        kind: 'require',
      },
      {
        icon: 'store',
        label: 'State boundary',
        detail: 'Spent-token and budget stores belong to the deployment.',
        href: `${GH}/cmd/tamayo/state.go`,
        kind: 'config',
      },
      {
        icon: 'crypto',
        label: 'Shared packages',
        detail: 'tokenprofile · tokenauth · tokenservice on the host.',
        kind: 'build',
      },
    ],
  },
  {
    id: 'baremetal',
    title: 'TamaGo bare metal',
    tone: 'baremetal',
    items: [
      {
        icon: 'board',
        label: 'QEMU / board',
        detail: 'sifive_u riscv64 demo and supported targets.',
        href: `${GH}/cmd/qemudemo/main.go`,
        kind: 'config',
      },
      {
        icon: 'kernel',
        label: 'TamaGo unikernel',
        detail: 'Go becomes the firmware; no host OS in the path.',
        kind: 'require',
      },
      {
        icon: 'shield',
        label: 'PoMFRIT / MAYO',
        detail: 'Blind path boots and verifies on device.',
        kind: 'build',
      },
      {
        icon: 'log',
        label: 'logging',
        detail: 'Compact console handler without a host service.',
        href: `${GH}/logging/logging.go`,
        kind: 'build',
      },
      {
        icon: 'api',
        label: 'cgo-free library',
        detail: 'Same package set for host Go and GOOS=tamago.',
        href: `${GH}/README.md`,
        kind: 'build',
      },
      {
        icon: 'crypto',
        label: 'Measured binary',
        detail: 'A short path from source to the program allowed to mint.',
        kind: 'config',
      },
    ],
  },
];
