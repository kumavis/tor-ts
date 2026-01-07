export type GetTime = () => number;

export const getTime: GetTime = () => Date.now();
