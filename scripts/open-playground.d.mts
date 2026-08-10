export function optionValue(name: string): string | undefined;
export function normalizeBaseUrl(value: string | undefined): string;
export function buildDemoUrl(baseUrl: string | undefined, route?: string): string;
export function buildDemoStatus(env?: Record<string, string | undefined>): {
  configured: boolean;
  hasApiKey: boolean;
  apiUrlOrigin: string | undefined;
};
export function openBrowser(url: string, spawnImpl?: (...args: any[]) => any): Promise<boolean>;
