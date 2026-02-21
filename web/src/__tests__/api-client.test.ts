/**
 * Tests for the API client module.
 *
 * Validates:
 * - URL construction for all endpoints
 * - Authorization header inclusion
 * - X-Request-ID header on POST requests
 * - Response structure validation
 * - Error handling
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  ApiError,
  clearAuthToken,
  getAuthToken,
  listAgents,
  approveRequest,
  denyRequest,
  sendInput,
  listPending,
  setAuthToken,
} from "../api/client";

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

// Mock import.meta.env
vi.stubGlobal("import", { meta: { env: { VITE_API_URL: "" } } });

// Mock localStorage
const localStorageMock = (() => {
  let store: Record<string, string> = {};
  return {
    getItem: (key: string) => store[key] ?? null,
    setItem: (key: string, value: string) => {
      store[key] = value;
    },
    removeItem: (key: string) => {
      delete store[key];
    },
    clear: () => {
      store = {};
    },
  };
})();
vi.stubGlobal("localStorage", localStorageMock);

// Mock crypto.getRandomValues
vi.stubGlobal("crypto", {
  getRandomValues: (arr: Uint8Array) => {
    for (let i = 0; i < arr.length; i++) {
      arr[i] = Math.floor(Math.random() * 256);
    }
    return arr;
  },
});

function mockSuccessResponse(data: unknown) {
  return {
    status: 200,
    json: () => Promise.resolve({ ok: true, message: "success", data }),
  };
}

function mockErrorResponse(status: number, message: string) {
  return {
    status,
    json: () => Promise.resolve({ ok: false, message }),
  };
}

describe("Auth token management", () => {
  beforeEach(() => {
    localStorageMock.clear();
  });

  it("stores and retrieves auth token", () => {
    setAuthToken("test-token-123");
    expect(getAuthToken()).toBe("test-token-123");
  });

  it("returns null when no token set", () => {
    expect(getAuthToken()).toBeNull();
  });

  it("clears auth token", () => {
    setAuthToken("test-token");
    clearAuthToken();
    expect(getAuthToken()).toBeNull();
  });
});

describe("API client - GET requests", () => {
  beforeEach(() => {
    mockFetch.mockReset();
    localStorageMock.clear();
  });

  afterEach(() => {
    localStorageMock.clear();
  });

  it("constructs correct URL for listAgents", async () => {
    mockFetch.mockResolvedValueOnce(mockSuccessResponse([]));

    await listAgents();

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("/v1/agents");
  });

  it("includes Authorization header when token is set", async () => {
    setAuthToken("my-secret-token");
    mockFetch.mockResolvedValueOnce(mockSuccessResponse([]));

    await listAgents();

    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers["Authorization"]).toBe("Bearer my-secret-token");
  });

  it("omits Authorization header when no token", async () => {
    mockFetch.mockResolvedValueOnce(mockSuccessResponse([]));

    await listAgents();

    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers["Authorization"]).toBeUndefined();
  });

  it("does not include X-Request-ID on GET requests", async () => {
    mockFetch.mockResolvedValueOnce(mockSuccessResponse([]));

    await listAgents();

    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers["X-Request-ID"]).toBeUndefined();
  });

  it("returns empty array when data is not an array", async () => {
    mockFetch.mockResolvedValueOnce(mockSuccessResponse("not an array"));

    const result = await listAgents();
    expect(result).toEqual([]);
  });

  it("returns agents when data is valid", async () => {
    const agents = [
      {
        name: "claude-1",
        status: "Running",
        pending_count: 0,
        uptime_secs: 3600,
        driver: "ClaudeCode",
        enabled: true,
      },
    ];
    mockFetch.mockResolvedValueOnce(mockSuccessResponse(agents));

    const result = await listAgents();
    expect(result).toEqual(agents);
  });
});

describe("API client - POST requests", () => {
  beforeEach(() => {
    mockFetch.mockReset();
    localStorageMock.clear();
  });

  it("includes X-Request-ID on POST requests (approve)", async () => {
    mockFetch.mockResolvedValueOnce(
      mockSuccessResponse(null),
    );

    await approveRequest("test-uuid");

    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers["X-Request-ID"]).toBeDefined();
    expect(headers["X-Request-ID"]!.length).toBe(32); // 16 bytes = 32 hex chars
  });

  it("constructs correct URL for approve", async () => {
    mockFetch.mockResolvedValueOnce(mockSuccessResponse(null));

    await approveRequest("abc-123");

    const [url] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("/v1/pending/abc-123/approve");
  });

  it("constructs correct URL for deny", async () => {
    mockFetch.mockResolvedValueOnce(mockSuccessResponse(null));

    await denyRequest("abc-123", "too risky");

    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("/v1/pending/abc-123/deny");
    expect(init.method).toBe("POST");
  });

  it("sends JSON body for sendInput", async () => {
    mockFetch.mockResolvedValueOnce(mockSuccessResponse(null));

    await sendInput("hello agent");

    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(init.body as string)).toEqual({ text: "hello agent" });
  });

  it("sends deny reason in body when provided", async () => {
    mockFetch.mockResolvedValueOnce(mockSuccessResponse(null));

    await denyRequest("abc-123", "too dangerous");

    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(init.body as string)).toEqual({ reason: "too dangerous" });
  });
});

describe("API client - Error handling", () => {
  beforeEach(() => {
    mockFetch.mockReset();
    localStorageMock.clear();
  });

  it("throws ApiError on error response", async () => {
    mockFetch.mockResolvedValueOnce(mockErrorResponse(401, "unauthorized"));

    await expect(listAgents()).rejects.toThrow(ApiError);
  });

  it("throws ApiError with correct status", async () => {
    mockFetch.mockResolvedValueOnce(mockErrorResponse(401, "unauthorized"));

    try {
      await listAgents();
      expect.fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(ApiError);
      const apiError = e as ApiError;
      expect(apiError.status).toBe(401);
      expect(apiError.message).toBe("unauthorized");
    }
  });

  it("throws on invalid response structure", async () => {
    mockFetch.mockResolvedValueOnce({
      status: 200,
      json: () => Promise.resolve({ unexpected: "shape" }),
    });

    await expect(listAgents()).rejects.toThrow("Invalid response structure");
  });

  it("handles pending endpoint with nested data", async () => {
    mockFetch.mockResolvedValueOnce({
      status: 200,
      json: () =>
        Promise.resolve({
          ok: true,
          message: "status",
          data: {
            pending: [
              { id: "uuid-1", raw_prompt: "Allow?", agent_name: "claude-1" },
            ],
          },
        }),
    });

    const result = await listPending();
    expect(result).toHaveLength(1);
    expect(result[0]!.id).toBe("uuid-1");
  });

  it("handles pending endpoint with array data", async () => {
    mockFetch.mockResolvedValueOnce({
      status: 200,
      json: () =>
        Promise.resolve({
          ok: true,
          message: "pending",
          data: [
            { id: "uuid-1", raw_prompt: "Allow?", agent_name: "claude-1" },
          ],
        }),
    });

    const result = await listPending();
    expect(result).toHaveLength(1);
  });

  it("handles pending endpoint with no data", async () => {
    mockFetch.mockResolvedValueOnce({
      status: 200,
      json: () =>
        Promise.resolve({
          ok: true,
          message: "status",
          data: { status: "running" },
        }),
    });

    const result = await listPending();
    expect(result).toEqual([]);
  });
});

describe("API client - URL encoding", () => {
  beforeEach(() => {
    mockFetch.mockReset();
    localStorageMock.clear();
  });

  it("encodes special characters in approval IDs", async () => {
    mockFetch.mockResolvedValueOnce(mockSuccessResponse(null));

    await approveRequest("id/with/slashes");

    const [url] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("id%2Fwith%2Fslashes");
    expect(url).not.toContain("id/with/slashes/approve");
  });
});

describe("API client - Response validation", () => {
  beforeEach(() => {
    mockFetch.mockReset();
    localStorageMock.clear();
  });

  it("validates CommandResponse shape: missing ok field", async () => {
    mockFetch.mockResolvedValueOnce({
      status: 200,
      json: () => Promise.resolve({ message: "no ok field" }),
    });

    await expect(listAgents()).rejects.toThrow("Invalid response structure");
  });

  it("validates CommandResponse shape: missing message field", async () => {
    mockFetch.mockResolvedValueOnce({
      status: 200,
      json: () => Promise.resolve({ ok: true }),
    });

    await expect(listAgents()).rejects.toThrow("Invalid response structure");
  });

  it("validates CommandResponse shape: null body", async () => {
    mockFetch.mockResolvedValueOnce({
      status: 200,
      json: () => Promise.resolve(null),
    });

    await expect(listAgents()).rejects.toThrow("Invalid response structure");
  });
});
