import type { RuntimeStackItem } from '../data/runtimeStacks';

const paths: Record<RuntimeStackItem['icon'], string> = {
  app: 'M7 3h10a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2zm5 16.2a1.1 1.1 0 1 0 0-2.2 1.1 1.1 0 0 0 0 2.2z',
  api: 'M4 8h4v8H4V8zm6-2h4v12h-4V6zm6 4h4v8h-4v-8z',
  policy: 'M12 3l8 3v5c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10V6l8-3zm0 4.2l-4.5 1.7v3.4c0 3.1 2 5.4 4.5 6.4 2.5-1 4.5-3.3 4.5-6.4V9L12 7.2z',
  mail: 'M3 6.5A2.5 2.5 0 0 1 5.5 4h13A2.5 2.5 0 0 1 21 6.5v11a2.5 2.5 0 0 1-2.5 2.5h-13A2.5 2.5 0 0 1 3 17.5v-11zm2.2.7 6.3 4.4a.9.9 0 0 0 1 0l6.3-4.4H5.2z',
  key: 'M14.5 8.5a3.5 3.5 0 1 1-2.4 6H8l-1.2 1.2H4.5V13l4.2-4.2a3.5 3.5 0 0 1 5.8-.3zm1.2 2.2a1.2 1.2 0 1 0 0 2.4 1.2 1.2 0 0 0 0-2.4z',
  crypto: 'M12 2l2.4 4.9 5.4.8-3.9 3.8.9 5.4L12 14.8 7.2 17l.9-5.4L4.2 7.7l5.4-.8L12 2z',
  issuer: 'M4 20V6.5L12 3l8 3.5V20h-5v-6H9v6H4zm5-8h6V8.2l-3-1.3-3 1.3V12z',
  burn: 'M12 2c2.4 3.2 5.8 5.4 5.8 9.2A5.8 5.8 0 0 1 12 17a5.8 5.8 0 0 1-5.8-5.8C6.2 7.4 9.6 5.2 12 2zm0 8.2c.9 1.1 1.8 1.9 1.8 3.1A1.8 1.8 0 0 1 12 15.1a1.8 1.8 0 0 1-1.8-1.8c0-1.2.9-2 1.8-3.1z',
  tpm: 'M5 7h14v10H5V7zm2 2v6h10V9H7zm3 1.5h4v3h-4v-3zM9 4h6v2H9V4zm0 14h6v2H9v-2z',
  cloud: 'M7.5 18A4.5 4.5 0 0 1 7.2 9a5.5 5.5 0 0 1 10.5 1.4A3.8 3.8 0 0 1 17.5 18H7.5z',
  shield: 'M12 3l8 3v5c0 5.2-3.5 9-8 10.5C7.5 20 4 16.2 4 11V6l8-3zm0 4.5v9.2c2.7-1 5-3.5 5-7.2V8L12 7.5z',
  log: 'M5 4h14v16H5V4zm3 3v2h8V7H8zm0 4v2h8v-2H8zm0 4v2h5v-2H8z',
  tee: 'M4 8h16v10H4V8zm2 2v6h12v-6H6zm3-4h6v2H9V6zm0 12h6v2H9v-2zM11 11h2v2h-2v-2z',
  board: 'M3 6h18v12H3V6zm2 2v8h14V8H5zm3 2h2v4H8v-4zm4 0h2v4h-2v-4zm4 0h2v4h-2v-4z',
  kernel: 'M8 3h8v3h3v5h-3v2h3v5h-3v3H8v-3H5v-5h3v-2H5V6h3V3zm2 2v2h4V5h-4zm0 12v2h4v-2h-4z',
  store: 'M4 7l1.5-3h13L20 7v2H4V7zm0 3h16v10H4V10zm3 2v6h2v-6H7zm4 0v6h2v-6h-2zm4 0v6h2v-6h-2z',
};

export function RuntimeStackIcon(props: { name: RuntimeStackItem['icon'] }) {
  return (
    <svg class="runtime-ico" viewBox="0 0 24 24" aria-hidden="true">
      <path d={paths[props.name]} fill="currentColor" />
    </svg>
  );
}
