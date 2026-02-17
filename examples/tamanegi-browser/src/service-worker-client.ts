/**
 * Service worker registration and Tor client proxy factory.
 * Handles registration, waiting for first-load activation, and controller updates.
 */

import { TorServiceWorkerClient } from './tor-sw-client.ts';

export type RegisterTorServiceWorkerOptions = {
  scope?: string;
  /** Timeout in ms for waiting for the SW to activate on first load. Default 15000. */
  activationTimeoutMs?: number;
};

/**
 * Register the Tor service worker and return a client when it is active.
 * On first load, waits for the installing worker to reach 'activated'.
 * Returns null if service workers are unsupported or registration/activation fails.
 */
export async function registerTorServiceWorker(
  scriptUrl: string | URL,
  options: RegisterTorServiceWorkerOptions = {}
): Promise<TorServiceWorkerClient | null> {
  if (!('serviceWorker' in navigator)) {
    return null;
  }

  const { scope = '/', activationTimeoutMs = 15000 } = options;

  try {
    const reg = await navigator.serviceWorker.register(scriptUrl, {
      type: 'module',
      scope,
    });

    let active: ServiceWorker | null = reg.active ?? navigator.serviceWorker.controller;

    if (!active && (reg.installing || reg.waiting)) {
      const worker = reg.installing ?? reg.waiting!;
      active = await new Promise<ServiceWorker | null>((resolve, reject) => {
        const timeout = setTimeout(
          () => reject(new Error('Service worker activation timeout')),
          activationTimeoutMs
        );
        const onStateChange = (): void => {
          if (worker.state === 'activated') {
            clearTimeout(timeout);
            worker.removeEventListener('statechange', onStateChange);
            resolve(reg.active ?? worker);
          }
        };
        worker.addEventListener('statechange', onStateChange);
        if (worker.state === 'activated') {
          clearTimeout(timeout);
          worker.removeEventListener('statechange', onStateChange);
          resolve(reg.active ?? worker);
        }
      });
    }

    if (!active) {
      await (reg as ServiceWorkerRegistration & { ready: Promise<ServiceWorker> }).ready;
      active = reg.active ?? navigator.serviceWorker.controller;
    }

    if (!active) {
      return null;
    }

    const client = new TorServiceWorkerClient(active);

    navigator.serviceWorker.addEventListener('controllerchange', () => {
      if (navigator.serviceWorker.controller) {
        client.setController(navigator.serviceWorker.controller);
      }
    });

    return client;
  } catch {
    return null;
  }
}
