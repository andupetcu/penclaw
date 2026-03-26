/**
 * Shared HTTP utilities: concurrency semaphore, SPA baseline detection, request helpers.
 */

export class Semaphore {
  private queue: Array<() => void> = [];
  private active = 0;

  constructor(private readonly limit: number) {}

  async acquire(): Promise<void> {
    if (this.active < this.limit) {
      this.active++;
      return;
    }
    return new Promise<void>((resolve) => {
      this.queue.push(resolve);
    });
  }

  release(): void {
    this.active--;
    const next = this.queue.shift();
    if (next) {
      this.active++;
      next();
    }
  }

  async run<T>(fn: () => Promise<T>): Promise<T> {
    await this.acquire();
    try {
      return await fn();
    } finally {
      this.release();
    }
  }
}

/**
 * Compares two response bodies for similarity. Used to detect SPA catch-all routing
 * where every path returns the same HTML shell.
 */
export function isSimilarResponse(bodyA: string, bodyB: string): boolean {
  if (bodyA === bodyB) return true;

  const lenA = bodyA.length;
  const lenB = bodyB.length;
  if (lenA === 0 || lenB === 0) return false;

  const ratio = Math.min(lenA, lenB) / Math.max(lenA, lenB);
  if (ratio < 0.9) return false;

  // Compare the first 500 chars (the <head> / shell is usually identical in SPAs)
  const headA = bodyA.slice(0, 500).replace(/\s+/g, " ");
  const headB = bodyB.slice(0, 500).replace(/\s+/g, " ");
  return headA === headB;
}

/**
 * Fetch a URL with optional delay, timeout, and User-Agent.
 */
export async function fetchWithDelay(
  url: string,
  options: {
    method?: string;
    headers?: Record<string, string>;
    timeoutMs?: number;
    delayMs?: number;
  } = {},
): Promise<{ status: number; body: string; headers: Headers }> {
  if (options.delayMs && options.delayMs > 0) {
    await new Promise((r) => setTimeout(r, options.delayMs));
  }

  const response = await fetch(url, {
    method: options.method ?? "GET",
    redirect: "follow",
    signal: AbortSignal.timeout(options.timeoutMs ?? 5_000),
    headers: {
      "User-Agent": "PenClaw/0.1.0 Security Scanner",
      ...options.headers,
    },
  });

  const body = await response.text();
  return { status: response.status, body, headers: response.headers };
}

/**
 * Fetch SPA baseline by requesting a random non-existent path.
 * Returns the body text if status 200, or null.
 */
export async function fetchSpaBaseline(baseUrl: string): Promise<string | null> {
  try {
    const randomPath = `/__penclaw_baseline_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    const url = new URL(randomPath, baseUrl).href;
    const { status, body } = await fetchWithDelay(url);
    return status === 200 ? body : null;
  } catch {
    return null;
  }
}
