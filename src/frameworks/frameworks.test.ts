import { describe, it, expect } from "vitest";
import type { Finding, FrameworkTags } from "../types";
import { OWASP_LLM_2025, CWE, ATLAS_TACTICS, ATTACK } from "./catalog";
import { tagFinding, tagChain, coverageSummary } from "./tagger";

/** Minimal Finding builder for coverage tests. */
function finding(id: string, frameworks: FrameworkTags): Finding {
  return {
    id,
    layer: "code",
    technique: id,
    location: "x:1",
    severity: "high",
    status: "found",
    frameworks,
    evidence: {},
    blindSpot: false,
  };
}

describe("catalog", () => {
  it("has the full OWASP-LLM 2025 list, in order", () => {
    expect(Object.keys(OWASP_LLM_2025)).toEqual([
      "LLM01",
      "LLM02",
      "LLM03",
      "LLM04",
      "LLM05",
      "LLM06",
      "LLM07",
      "LLM08",
      "LLM09",
      "LLM10",
    ]);
    expect(OWASP_LLM_2025.LLM01).toBe("Prompt Injection");
    expect(OWASP_LLM_2025.LLM02).toBe("Sensitive Information Disclosure");
    expect(OWASP_LLM_2025.LLM07).toBe("System Prompt Leakage");
  });

  it("carries the required CWEs", () => {
    expect(CWE["CWE-89"]).toMatch(/SQL/i);
    expect(CWE["CWE-22"]).toMatch(/Path Traversal/i);
    expect(CWE["CWE-798"]).toMatch(/Hard-coded/i);
    expect(CWE["CWE-918"]).toMatch(/SSRF|Request Forgery/i);
  });

  it("stores ATLAS as tactic names only", () => {
    expect(ATLAS_TACTICS.PROMPT_INJECTION).toBe("Prompt Injection");
    expect(ATLAS_TACTICS.EXFILTRATION_VIA_ML_INFERENCE_API).toBe(
      "Exfiltration via ML Inference API",
    );
    // No AML.Txxxx codes should be baked in as values.
    for (const name of Object.values(ATLAS_TACTICS)) {
      expect(name).not.toMatch(/AML\.T\d+/);
    }
  });

  it("has the ATT&CK exfiltration reference", () => {
    expect(ATTACK.T1041).toBe("Exfiltration Over C2 Channel");
    expect(ATTACK.TA0010).toBe("Exfiltration");
  });
});

describe("tagFinding — code layer", () => {
  it("maps SQL injection / sqli to CWE-89", () => {
    expect(tagFinding("SQL Injection", "code").cwe).toEqual(["CWE-89"]);
    expect(tagFinding("sqli", "code").cwe).toEqual(["CWE-89"]);
  });

  it("maps path traversal to CWE-22", () => {
    expect(tagFinding("Path Traversal", "code").cwe).toEqual(["CWE-22"]);
  });

  it("maps hardcoded secret / credential to CWE-798", () => {
    expect(tagFinding("hardcoded secret", "code").cwe).toEqual(["CWE-798"]);
    expect(tagFinding("hardcoded credential", "code").cwe).toEqual(["CWE-798"]);
  });

  it("maps ssrf to CWE-918", () => {
    expect(tagFinding("SSRF", "code").cwe).toEqual(["CWE-918"]);
  });
});

describe("tagFinding — agent layer", () => {
  it("maps prompt injection to LLM01 + ATLAS Prompt Injection", () => {
    const t = tagFinding("prompt injection", "agent");
    expect(t.owasp_llm).toEqual(["LLM01"]);
    expect(t.atlas).toEqual(["Prompt Injection"]);
  });

  it("maps excessive agency / tool misuse to LLM06", () => {
    expect(tagFinding("excessive agency", "agent").owasp_llm).toEqual(["LLM06"]);
    expect(tagFinding("tool misuse", "agent").owasp_llm).toEqual(["LLM06"]);
  });

  it("maps data leak / exfiltration / sensitive disclosure to LLM02 + T1041 + ATLAS", () => {
    for (const technique of ["data leak", "exfiltration", "sensitive disclosure"]) {
      const t = tagFinding(technique, "agent");
      expect(t.owasp_llm).toEqual(["LLM02"]);
      expect(t.attack).toEqual(["T1041"]);
      expect(t.atlas).toEqual(["Exfiltration via ML Inference API"]);
    }
  });
});

describe("tagFinding — robustness", () => {
  it("returns empty arrays for an unknown technique, never throws", () => {
    const t = tagFinding("totally unknown thing", "code");
    expect(t).toEqual({ owasp_llm: [], cwe: [], atlas: [], attack: [] });
  });

  it("is case-insensitive and scans context too", () => {
    expect(tagFinding("SQLi", "code").cwe).toEqual(["CWE-89"]);
    const t = tagFinding("weird label", "agent", "this was a prompt injection payload");
    expect(t.owasp_llm).toEqual(["LLM01"]);
  });

  it("tolerates empty / missing input", () => {
    expect(() => tagFinding("", "code")).not.toThrow();
    expect(tagFinding("", "code")).toEqual({
      owasp_llm: [],
      cwe: [],
      atlas: [],
      attack: [],
    });
  });
});

describe("tagChain — cross-layer merge", () => {
  it("merges the headline chained attack and dedupes", () => {
    const t = tagChain([
      "prompt injection",
      "excessive agency",
      "sql injection",
      "exfiltration",
    ]);
    expect(t.owasp_llm.sort()).toEqual(["LLM01", "LLM02", "LLM06"]);
    expect(t.cwe).toEqual(["CWE-89"]);
    expect(t.atlas.sort()).toEqual(
      ["Exfiltration via ML Inference API", "Prompt Injection"].sort(),
    );
    expect(t.attack).toEqual(["T1041"]);
  });

  it("dedupes repeated techniques", () => {
    const t = tagChain(["sqli", "sql injection", "sqli"]);
    expect(t.cwe).toEqual(["CWE-89"]);
  });

  it("handles an empty chain", () => {
    expect(tagChain([])).toEqual({ owasp_llm: [], cwe: [], atlas: [], attack: [] });
  });
});

describe("coverageSummary", () => {
  it("counts distinct ids across findings", () => {
    const findings: Finding[] = [
      finding("F1", tagFinding("prompt injection", "agent")),
      finding("F2", tagFinding("exfiltration", "agent")),
      finding("F3", tagFinding("sql injection", "code")),
      finding("F4", tagFinding("path traversal", "code")),
      finding("F5", tagFinding("hardcoded secret", "code")),
    ];
    // OWASP-LLM: LLM01, LLM02 = 2 · CWE: 89, 22, 798 = 3
    // ATLAS: Prompt Injection, Exfiltration via ML Inference API = 2 · ATT&CK: T1041 = 1
    expect(coverageSummary(findings)).toBe(
      "OWASP-LLM: 2 · CWE: 3 · ATLAS: 2 · ATT&CK: 1",
    );
  });

  it("does not double-count ids shared across findings", () => {
    const findings: Finding[] = [
      finding("F1", tagFinding("sqli", "code")),
      finding("F2", tagFinding("sql injection", "code")),
    ];
    expect(coverageSummary(findings)).toBe(
      "OWASP-LLM: 0 · CWE: 1 · ATLAS: 0 · ATT&CK: 0",
    );
  });

  it("handles an empty finding set", () => {
    expect(coverageSummary([])).toBe("OWASP-LLM: 0 · CWE: 0 · ATLAS: 0 · ATT&CK: 0");
  });
});
