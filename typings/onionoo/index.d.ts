declare module 'onionoo' {
  export type OnionooDetailsQuery = Record<string, unknown>;

  export type OnionooDetailsResponse = {
    body: {
      relays: unknown[];
      bridges?: unknown[];
    };
  };

  export default class Onionoo {
    details(query: OnionooDetailsQuery): Promise<OnionooDetailsResponse>;
  }
}
