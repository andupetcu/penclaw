import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { DiscoveredEndpoint } from "../src/types/index.js";

// We need to mock undici's request before importing the module
const mockRequest = vi.fn();

vi.mock("undici", () => ({
  request: (...args: unknown[]) => mockRequest(...args),
}));

// Import after mocking
const { detectTimeBased, detectBooleanBased } = await import("../src/crawl/api-fuzzer.js");

function makeEndpoint(overrides?: Partial<DiscoveredEndpoint>): DiscoveredEndpoint {
  return {
    url: "https://example.com/api/search?q=test",
    method: "GET",
    parameters: ["q"],
    ...overrides,
  };
}

function mockBody(text: string) {
  return { text: () => Promise.resolve(text) };
}

describe("detectTimeBased", () => {
  beforeEach(() => {
    mockRequest.mockReset();
  });

  it("detects time-based blind SQLi when response is delayed", async () => {
    let callCount = 0;

    mockRequest.mockImplementation(() => {
      callCount++;
      if (callCount <= 2) {
        // Baseline calls — fast response
        return Promise.resolve({ statusCode: 200, body: mockBody("ok") });
      }
      // Time-delay payload — simulate 6 second delay
      return new Promise((resolve) =>
        setTimeout(() => resolve({ statusCode: 200, body: mockBody("ok") }), 100),
      );
    });

    // We need to mock Date.now to simulate timing
    const originalNow = Date.now;
    let nowValue = 1000;
    vi.spyOn(Date, "now").mockImplementation(() => {
      const current = nowValue;
      // Baseline calls: fast (50ms each)
      // Payload call: slow (6000ms)
      if (callCount <= 2) {
        nowValue += 50;
      } else {
        nowValue += 6000;
      }
      return current;
    });

    const findings = await detectTimeBased(makeEndpoint());

    Date.now = originalNow;
    vi.restoreAllMocks();

    expect(findings.length).toBe(1);
    expect(findings[0]!.ruleId).toBe("fuzzer-blind-sqli-time-based");
    expect(findings[0]!.severity).toBe("critical");
  });

  it("returns no findings when responses are fast", async () => {
    mockRequest.mockResolvedValue({ statusCode: 200, body: mockBody("ok") });

    const findings = await detectTimeBased(makeEndpoint());
    expect(findings.length).toBe(0);
  });

  it("returns no findings for endpoints with no parameters", async () => {
    const findings = await detectTimeBased(makeEndpoint({ parameters: [] }));
    expect(findings.length).toBe(0);
    expect(mockRequest).not.toHaveBeenCalled();
  });

  it("handles baseline request failure gracefully", async () => {
    mockRequest.mockRejectedValue(new Error("Connection refused"));

    const findings = await detectTimeBased(makeEndpoint());
    expect(findings.length).toBe(0);
  });
});

describe("detectBooleanBased", () => {
  beforeEach(() => {
    mockRequest.mockReset();
  });

  it("detects boolean-based blind when true/false responses differ significantly", async () => {
    let callIndex = 0;
    mockRequest.mockImplementation(() => {
      callIndex++;
      // Alternate between true (long) and false (short) responses
      if (callIndex % 2 === 1) {
        // True condition — large response
        return Promise.resolve({
          statusCode: 200,
          body: mockBody("A".repeat(1000)),
        });
      }
      // False condition — small response
      return Promise.resolve({
        statusCode: 200,
        body: mockBody("B".repeat(100)),
      });
    });

    const findings = await detectBooleanBased(makeEndpoint());
    expect(findings.length).toBe(1);
    expect(findings[0]!.ruleId).toBe("fuzzer-blind-sqli-boolean-based");
    expect(findings[0]!.severity).toBe("high");
    expect(findings[0]!.metadata?.diffPercent).toBeGreaterThan(20);
  });

  it("returns no findings when responses are similar in length", async () => {
    mockRequest.mockResolvedValue({
      statusCode: 200,
      body: mockBody("consistent response body here"),
    });

    const findings = await detectBooleanBased(makeEndpoint());
    expect(findings.length).toBe(0);
  });

  it("returns no findings for endpoints with no parameters", async () => {
    const findings = await detectBooleanBased(makeEndpoint({ parameters: [] }));
    expect(findings.length).toBe(0);
  });

  it("handles request failure gracefully", async () => {
    mockRequest.mockRejectedValue(new Error("Network error"));

    const findings = await detectBooleanBased(makeEndpoint());
    expect(findings.length).toBe(0);
  });
});
