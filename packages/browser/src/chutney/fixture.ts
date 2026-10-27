import type { DirectoryAuthorityIdentity } from 'tor';
import type {} from 'vitest';

export type ChutneyBrowserFixture = {
  relayUrl: string;
  onionUrl: string;
  expectedBody: string;
  trustedAuthorities: DirectoryAuthorityIdentity[];
};

declare module 'vitest' {
  export interface ProvidedContext {
    chutney: ChutneyBrowserFixture;
  }
}
