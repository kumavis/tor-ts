/**
 * Type declarations for Vite's ?raw suffix imports.
 * This allows importing files as raw strings.
 */
declare module '*?raw' {
  const content: string;
  export default content;
}

declare module '*.txt?raw' {
  const content: string;
  export default content;
}
