import { describe, it, expect, vi, afterEach } from "vitest";
import { analyzeOptions, formatReport, reportAtStartup, createProxyWatcher } from "../src/core/doctor";

const ids = (o: Parameters<typeof analyzeOptions>[0]) => analyzeOptions(o).map((f) => f.id);

describe("analyzeOptions", () => {
  it("flags missing protections", () => {
    expect(ids({})).toEqual(expect.arrayContaining(["rate-limit-off", "headers-off"]));
  });
  it("is quiet for a solid config", () => {
    const f = analyzeOptions({ rateLimit: true, protectHeaders: true, cors: ["https://a.com"], xss: true });
    expect(f.filter((x) => x.severity !== "info")).toEqual([]);
  });
  it("flags cors problems", () => {
    expect(ids({ cors: true })).toContain("cors-wildcard");
    expect(ids({ cors: ["example.com"] })).toContain("cors-origin-no-scheme");
    const f = analyzeOptions({ cors: { origin: true, credentials: true } });
    expect(f.find((x) => x.id === "cors-credentials-wildcard")?.severity).toBe("error");
  });
  it("flags ineffective blacklist entries", () => {
    expect(ids({ ipBlacklist: ["10.0.0.0/8"] })).toContain("blacklist-cidr");
    expect(ids({ ipBlacklist: ["not-an-ip"] })).toContain("blacklist-invalid");
    expect(ids({ ipBlacklist: ["::ffff:1.2.3.4", "1.2.3.4", "2001:db8::1"] })).not.toContain("blacklist-invalid");
  });
  it("flags disabled helmet parts, noop xss and unredacted logs", () => {
    expect(ids({ protectHeaders: { contentSecurityPolicy: false } })).toContain("csp-disabled");
    expect(ids({ xss: { body: false, query: false, params: false } })).toContain("xss-noop");
    expect(ids({ requestLogging: { redactQuery: false } })).toContain("log-redaction-off");
  });
});

describe("input hardening findings", () => {
  it("notes protections that are off and misconfigurations", () => {
    expect(ids({})).toEqual(expect.arrayContaining(["nosql-off", "hpp-off"]));
    expect(ids({ noSqlInjection: true, parameterPollution: true })).not.toEqual(expect.arrayContaining(["nosql-off", "hpp-off"]));
    expect(ids({ noSqlInjection: { body: false, query: false } })).toContain("nosql-noop");
    expect(ids({ noSqlInjection: { mode: "strip" } })).toContain("nosql-strip");
  });
});

describe("startup report", () => {
  const env = process.env.NODE_ENV;
  afterEach(() => { process.env.NODE_ENV = env; });

  it("prints a summary and warnings through the custom logger", () => {
    process.env.NODE_ENV = "production";
    const lines: string[] = [];
    reportAtStartup({ cors: true, doctor: { logger: (m) => lines.push(m) } });
    expect(lines[0]).toContain("active: cors");
    expect(lines.join("\n")).toContain("WARN cors-wildcard");
    expect(lines.join("\n")).not.toContain("INFO");
  });
  it("is silent with doctor:false or NODE_ENV=test", () => {
    const spy = vi.fn();
    process.env.NODE_ENV = "production";
    reportAtStartup({ doctor: false });
    process.env.NODE_ENV = "test";
    reportAtStartup({ doctor: { logger: spy } });
    expect(spy).not.toHaveBeenCalled();
  });
  it("verbose report includes info findings", () => {
    const o = { rateLimit: true as const };
    expect(formatReport(o, analyzeOptions(o), true).join("\n")).toContain("INFO rate-limit-memory");
  });
});

describe("proxy watcher", () => {
  it("warns once when X-Forwarded-For is seen without trust proxy", () => {
    const prev = process.env.NODE_ENV; process.env.NODE_ENV = "production";
    const logs: string[] = [];
    const watch = createProxyWatcher({ rateLimit: true, doctor: { logger: (m) => logs.push(m) } });
    watch(true, false); watch(true, false); watch(false, false); watch(true, true);
    process.env.NODE_ENV = prev;
    expect(logs).toHaveLength(1);
    expect(logs[0]).toContain("proxy-untrusted");
  });
  it("stays quiet when no rate limit / blacklist is configured", () => {
    const logs: string[] = [];
    createProxyWatcher({ doctor: { logger: (m) => logs.push(m) } })(true, false);
    expect(logs).toHaveLength(0);
  });
});
