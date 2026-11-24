# Supply Chain Guardian — Visual Presentation Deck

![Architecture](architecture.svg)

---

## Slide 1: End-to-End Architecture & Dataflow

```mermaid
flowchart LR
  INPUT(["Target Input<br/>owner/repo · GitHub URL · Local"]) --> CLONE["Safe Git Ingestion<br/>Hooks Off · Depth 50"]
  CLONE --> PARSERS["9-Ecosystem Graph Engine<br/>npm · PyPI · Cargo · Maven+Tree<br/>Go · Ruby · PHP · ROS · Git"]
  CLONE --> CRAWLER["Parallel Shadow Crawler<br/>.py .js .ts .rs .java .go .rb"]
  CLONE --> MERKLE["4096B Chunk Merkle Tree<br/>+ HMAC Audit Ledger"]

  PARSERS & CRAWLER --> INTEL["Live Threat & Registry Feeds<br/>OSV.dev · CISA KEV · FIRST EPSS<br/>deps.dev · npm · PyPI · Maven"]
  INTEL & MERKLE --> FORMULA["Deterministic Risk Engine<br/>CVSS v3/v4 + Reachability + KEV"]

  FORMULA --> AGENTS["4 Specialist AI Agents<br/>Google GenAI SDK + Claude SDK<br/>Red · Integrity · Risk · Blue"]
  AGENTS --> GATE{"Human Gate OR<br/>Autonomous Mode"}
  GATE --> TESTGEN["Sandbox Test Generator<br/>GEMINI_API_FOR_TESTING"]
  TESTGEN --> DOCKER["Isolated Sandbox Validation<br/>Patch + Test + Auto-Merge"]
```

---

## Slide 2: Multi-Ecosystem Graph & Parallel Shadow Crawler

```mermaid
flowchart TD
  REPO["Repository Files (git ls-files)"] --> MAN["Declared Manifests & Lockfiles"]
  REPO --> SRC["Source Code Files (ThreadPoolExecutor)"]

  MAN --> M1["npm / pnpm / yarn"]
  MAN --> M2["PyPI / Poetry / uv / Pipfile"]
  MAN --> M3["Maven pom.xml + mvn dependency:tree"]
  MAN --> M4["Cargo · Go · Ruby · Composer · ROS"]

  SRC --> S1["Python AST/Imports + Dynamic top_level.txt"]
  SRC --> S2["JS/TS require & ES import"]
  SRC --> S3["Rust use/extern crate · Java import · Go · Ruby"]

  M1 & M2 & M3 & M4 --> DIFF{"Import Declared<br/>in Direct Graph?"}
  S1 & S2 & S3 --> DIFF

  DIFF -->|Yes| REACH["+15 Direct / +8 Transitive<br/>Reachability Score"]
  DIFF -->|No: Transitive Only| PHANTOM["SC8: Phantom Dependency"]
  DIFF -->|No: Missing Everywhere| SHADOW["SC8: Undeclared Shadow Dependency"]

  PHANTOM & SHADOW --> OSVCHK{"OSV.dev Check<br/>CVE or MAL-*?"}
  OSVCHK -->|MAL-* / CVE| CRIT["CRITICAL / HIGH Alert<br/>Block & Escalate"]
  OSVCHK -->|Clean| PIN["FIX-SHDW-* Auto-Patch<br/>Pin in requirements.txt / package.json / Cargo.toml / pom.xml"]
```

---

## Slide 3: Cryptographic 4096B Merkle Tree & Signed Audit Ledger

```mermaid
flowchart LR
  subgraph DEV["Legitimate Developer Workflow"]
    EDIT["Code Edit"] --> SIGN["Sign Baseline<br/>GUARDIAN_SIGNING_KEY"]
    SIGN --> CHUNKS["Split into 4096-Byte Chunks<br/>c_0, c_1, ..., c_n"]
    CHUNKS --> ROOT["Per-File SHA-256 Merkle Root<br/>+ Line Hashes"]
    ROOT --> HMAC["HMAC-SHA256 Signed<br/>.guardian/baseline.json"]
  end

  subgraph ATK["Silent Tamper / Rebase Attack"]
    MAL["Malicious Script / Rebase<br/>Modifies 1 Line (e.g. Payment URL)"] --> WATCH["Keyed Random-Chunk Sampler<br/>HMAC(K, nonce || file || i)"]
    HMAC --> WATCH
    WATCH --> PINPOINT["IT1: Exact Chunk, Byte Offset<br/>& Line Number Pinpointed"]
    PINPOINT --> IAGENT["Integrity Agent<br/>Reads Tampered Lines & Alerts"]
  end

  subgraph LED["Tamper-Evident Hash-Chained Ledger"]
    B0["Record #0<br/>prev: 0000...<br/>sig: HMAC(K, R_0)"] --> B1["Record #1 (Scan/Waiver)<br/>prev: R_0<br/>sig: HMAC(K, R_1)"]
    B1 --> B2["Record #2 (Auto-Merge)<br/>prev: R_1<br/>sig: HMAC(K, R_2)"]
  end
```

### Cryptographic Verification Equations

$$\text{MerkleLeaf}_i = \text{SHA256}\big(\text{FileBytes}[4096i : 4096(i+1)]\big), \qquad \text{SampleIdx} = \text{HMAC-SHA256}(K_{\text{sign}}, \text{nonce} \,\|\, \text{path} \,\|\, c) \bmod N$$

$$R_n = \text{SHA256}\big(n \,\|\, R_{n-1} \,\|\, \text{CanonicalJSON}(\text{Data}_n)\big), \qquad \text{HeadSig}_n = \text{HMAC-SHA256}(K_{\text{sign}}, R_n)$$

---

## Slide 4: Live Threat Intelligence & Mathematical Risk Engine

```mermaid
flowchart TD
  PURL["Canonical Component<br/>pkg:eco/name@version"] --> OSV["OSV.dev /v1/querybatch"]
  PURL --> DEPS["Google api.deps.dev<br/>+ Registry Search APIs"]
  PURL --> REGS["Official Registries<br/>npm · PyPI · Maven Central"]

  OSV -->|MAL-*| MAL["OSV-MAL: Known Malicious<br/>Category: malicious · Score: 100"]
  OSV -->|CVE / GHSA| CVE["CVSS v3.1 & CVSS v4.0 Calculator"]
  CVE --> KEV["CISA KEV + FIRST EPSS API"]

  DEPS --> TYPO["SC9: Multi-Eco Typosquat<br/>Damerau-Levenshtein · Homoglyph · Swap"]
  REGS -->|HTTP 404| PROV["SC10: Unknown Provenance / Confusion"]
  REGS -->|Age < 7d / 30d| AGE["SC11: Brand-New Release / Package"]

  MAL & KEV & TYPO & PROV & AGE --> SCORE["Deterministic Risk Formula (0-100)"]
```

### Core Scoring Equations

$$\text{RiskScore} = \min\!\left(100,\; \underbrace{40 \cdot \frac{\text{CVSS}}{10}}_{\text{0–40 pts}} + \underbrace{\begin{cases} 25 & \text{in CISA KEV} \\ 15 \cdot \text{EPSS} & \text{otherwise} \end{cases}}_{\text{0–25 pts}} + \underbrace{\begin{cases} 15 & \text{prod} \\ 3 & \text{dev} \end{cases}}_{\text{3–15 pts}} + \underbrace{\begin{cases} 15 & \text{direct import} \\ 8 & \text{transitive import} \\ 0 & \text{unimported} \end{cases}}_{\text{0–15 pts}} + \underbrace{\begin{cases} 5 & \text{direct} \\ 0 & \text{transitive} \end{cases}}_{\text{0–5 pts}}\right)$$

$$\text{IndicatorScore} = \text{clamp}_{[0,100]}\!\Big(W_{\text{rule}} + X_{\text{prod/dev}} + H_{\text{git\_commit}}\Big), \qquad \text{Confidence} = \frac{N_{\text{observed\_factors}}}{5}$$

---

## Slide 5: Multi-Agent System & Autonomous Test-Driven Mitigation

```mermaid
sequenceDiagram
  autonumber
  participant O as Orchestrator
  participant A as Attack & Integrity Agents
  participant R as Risk & Defense Agents
  participant G as Human Gate / Top-Bar Toggle
  participant T as Test Generator (GEMINI_API_FOR_TESTING)
  participant S as Sandbox & Auto-Merge

  O->>A: Findings (SC1-SC11, IT1-IT2, OSV-MAL)
  A->>A: Call read-only tools & verify citations (EV-*)
  A-->>O: Verified Facts vs Inferences + Forensic Attack Paths
  O->>R: Ranked Findings + Deterministic Fix Candidates
  R-->>O: Ordered Proposals (FIX-VULN, FIX-OVR, FIX-LOCK, FIX-SHDW, FIX-CI)
  O->>G: Present Diffs (or Auto-Approve if Autonomous Toggle ON)
  G->>T: Trigger Sandbox Validation
  T->>T: Discover Existing Tests OR Generate _guardian_smoke_test
  T->>S: Apply Patch + Run Tests in Isolated Copy
  S-->>O: Exit 0 -> Auto-Merge to Repo + Re-Sign Merkle Baseline & Ledger
```

---

## Slide 6: Complete Tech Stack, SDKs & Open Tools

```mermaid
flowchart TB
  subgraph SDK["Official AI & Agent SDKs"]
    GSDK["Google GenAI SDK<br/>(google-genai / google.genai)"]
    CSDK["Anthropic Claude SDK<br/>(anthropic Messages API)"]
    FALL["Deterministic Rule-Based<br/>Fallback Engine (--llm none)"]
  end

  subgraph OPEN["Open Security Feeds & Registries"]
    F1["OSV.dev Batch API"]
    F2["CISA KEV Catalog"]
    F3["FIRST EPSS API"]
    F4["Google deps.dev API"]
    F5["npm · PyPI · Maven Central<br/>Crates.io · RubyGems · Packagist"]
  end

  subgraph CORE["Core Runtime & Standards"]
    C1["Python 3.11+ · FastAPI · Uvicorn"]
    C2["Docker & Compose v2 Sandbox"]
    C3["CycloneDX 1.5 SBOM · PURL · CVSS v3.1 & v4.0"]
    C4["SHA-256 Merkle Trees · HMAC-SHA256 Chained Ledger"]
    C5["Force-Graph HTML5 Canvas Dashboard"]
  end

  SDK --> CORE
  OPEN --> CORE
```
