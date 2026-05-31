export interface DocVersion {
  id: string;
  name: string;
  label: string;
  isLatest?: boolean;
  isExperimental?: boolean;
  isDeprecated?: boolean;
  releaseNotesUrl?: string;
}
