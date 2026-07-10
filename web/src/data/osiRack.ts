export type OsiRackUnit = {
  id: string;
  href: string;
  layer: string;
  title: string;
  blurb: string;
  accent: string;
};

/** Full 1–8 stack — classic OSI 1–7 plus Agents on top. */
export const OSI_RACK_UNITS: OsiRackUnit[] = [
  {
    id: 'u1',
    href: '#tamago',
    layer: 'L1',
    title: 'TamaGo',
    blurb: 'Physical · bare-metal Go',
    accent: '#19b987',
  },
  {
    id: 'u2',
    href: '#tee',
    layer: 'L2',
    title: 'TEE',
    blurb: 'Link · enclaves & CVMs',
    accent: '#2368ff',
  },
  {
    id: 'u3',
    href: '#primitives',
    layer: 'L3',
    title: 'Crypto',
    blurb: 'Network · FAEST · MAYO · PoMFRIT',
    accent: '#f0b23f',
  },
  {
    id: 'u4',
    href: '#runtime',
    layer: 'L4',
    title: 'Runtime',
    blurb: 'Transport · runs everywhere',
    accent: '#7ab8ed',
  },
  {
    id: 'u5',
    href: '#session',
    layer: 'L5',
    title: 'Session',
    blurb: 'Issuance · blind · zero-knowledge',
    accent: '#f08c4a',
  },
  {
    id: 'u6',
    href: '#passes',
    layer: 'L6',
    title: 'Tokens',
    blurb: 'Presentation · narrow passes',
    accent: '#d94bc5',
  },
  {
    id: 'u7',
    href: '#policy',
    layer: 'L7',
    title: 'Policy',
    blurb: 'Application · mint rules',
    accent: '#e53d45',
  },
  {
    id: 'u8',
    href: '#agents',
    layer: 'L8',
    title: 'Agents',
    blurb: 'Principals · tools · code · scale',
    accent: '#a78bfa',
  },
];
