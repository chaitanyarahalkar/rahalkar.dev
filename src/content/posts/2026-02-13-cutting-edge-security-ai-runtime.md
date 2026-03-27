---
title: "Runtime Security for AI Agents: From Prompt Injection to Verifiable Toolchains"
published: 2026-02-13 16:30:00+00:00
draft: false
tags: ["security", "ai", "supply-chain", "attestation", "slsa", "sandbox"]
series: ""
---

AI agents are no longer just “LLMs with a chat UI.” They read from untrusted sources, invoke tools, write to stateful systems, and act across networks. That turns *prompt injection* into a **runtime security** problem. Below is a technical, source‑backed breakdown of the latest threats and the defenses that actually hold up.

---

## 1) Threats are no longer just “bad prompts”
Recent surveys show a *full-stack* threat model for agent ecosystems that spans input manipulation, model compromise, system/privacy attacks, and protocol‑level vulnerabilities (including agent‑to‑agent tooling and connector protocols) [1]. The key point: **the exploit path is often the toolchain, not the model output**.

### 1.1 Tool‑level prompt injection
The newest attacks focus on **coercing tool invocation** rather than forcing a visible jailbreak. A concrete example is **Log‑To‑Leak**, which injects prompts that cause agents to call a malicious logging tool that silently exfiltrates user queries, tool responses, and agent replies—while preserving task quality [2]. This is a big deal because it defeats naive “output‑based” detection.

### 1.2 Protocol‑layer exploits
The 2025 survey of LLM‑agent workflows explicitly highlights protocol weaknesses and mentions real incidents like *Toxic Agent Flow* in GitHub’s MCP server [1]. If your agent plugs into tools via MCP‑style servers, **tool transport and schema validation are now part of your threat surface**.

---

## 2) Prompt injection defenses: what actually works
Filtering and “just say no” prompts are not enough. The most promising approaches combine **detection, isolation, and least‑privilege tooling**.

### 2.1 PromptArmor (LLM‑based sanitization)
PromptArmor proposes a **separate LLM step** that detects and removes injected content before the main agent sees it. The paper reports **<1% false positives and <1% false negatives on AgentDojo**, and <1% attack success after sanitization, even against adaptive attacks [3]. That’s a practical baseline for high‑risk agents.

### 2.2 Agents Rule of Two (design‑level containment)
Meta’s “Agents Rule of Two” reframes the problem: you can’t safely allow *all three* of (A) untrusted input, (B) access to sensitive data, and (C) the ability to change state or communicate externally **in a single session**. If you need all three, you must add supervision or strong isolation [4]. It’s a design‑level control that remains valid even when detection fails.

---

## 3) Runtime security controls that matter in 2026
Here’s the minimum bar for a cutting‑edge runtime:

### 3.1 Capability‑based tools, not god‑mode APIs
- Split tools into **narrow capabilities** (read‑only vs write) with strict schemas.
- Avoid free‑form “shell” tools unless you can sandbox *and* audit them.

### 3.2 Egress control + per‑tool allowlists
If a tool can’t talk to the internet, it can’t exfiltrate. Runtime should enforce **deny‑by‑default** outbound network policies and allowlists per tool.

### 3.3 Retrieval tiering + poisoning detection
Poisoning isn’t just “bad answers”; it’s **behavior steering**. Separate trusted vs untrusted stores, label sources, and flag anomalous embedding clusters or sudden topic spikes [1].

---

## 4) Supply‑chain integrity for agents (SLSA + in‑toto)
The moment your agent’s tools or model artifacts can be replaced, everything above collapses. The answer is verifiable provenance:

- **SLSA** provides a framework and levels of assurance to prevent tampering and guarantee artifact integrity across your build pipeline [5].
- **in‑toto** provides a metadata standard that makes the whole chain (who did what, when, and in what order) transparent and verifiable [6].

Treat your agent like a build artifact with provenance, signatures, and attestations—*not* like a static config file.

---

## 5) A practical hardening checklist

**Runtime**
- [ ] Minimal tools with strict schemas and scoped permissions
- [ ] Per‑tool egress allowlists, deny‑by‑default
- [ ] Sandbox isolation + ephemeral credentials

**Input & Retrieval**
- [ ] Prompt injection detection (e.g., PromptArmor) in the preprocessing layer
- [ ] Trusted/untrusted data tiering + poisoning heuristics

**Supply Chain**
- [ ] Signed model/tool artifacts
- [ ] SLSA‑aligned CI + in‑toto attestations

---

## Final take
The dangerous misconception is that “prompt injection is an LLM problem.” It’s not. It’s a *runtime* problem with a supply‑chain and protocol surface. Secure agents the same way you secure any production system: **least privilege, isolation, provenance, and observability**.

---

## References
1. *From prompt injections to protocol exploits: Threats in LLM‑powered AI agents workflows* (2025) — ScienceDirect. https://www.sciencedirect.com/science/article/pii/S2405959525001997
2. *Log‑To‑Leak: Prompt Injection Attacks on Tool‑Using LLM Agents via Model Context Protocol* (2025) — OpenReview. https://openreview.net/forum?id=UVgbFuXPaO
3. *PromptArmor: Simple yet Effective Prompt Injection Defenses* (2025) — arXiv. https://arxiv.org/html/2507.15219v1
4. *Agents Rule of Two* (2025) — Meta AI blog (via Simon Willison). https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/
5. SLSA — Supply‑chain Levels for Software Artifacts. https://slsa.dev/
6. in‑toto — Software supply‑chain integrity framework. https://in-toto.io/
