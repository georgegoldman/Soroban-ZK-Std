import { DocVersion } from '../types/docs';

export const mockVersions: DocVersion[] = [
  {
    id: 'latest',
    name: 'latest',
    label: 'Latest (v1.2)',
    isLatest: true,
  },
  {
    id: 'v1.1',
    name: 'v1.1',
    label: 'v1.1',
  },
  {
    id: 'v1.0',
    name: 'v1.0',
    label: 'v1.0',
    isDeprecated: true,
  },
  {
    id: 'experimental',
    name: 'experimental',
    label: 'Experimental',
    isExperimental: true,
  },
];
