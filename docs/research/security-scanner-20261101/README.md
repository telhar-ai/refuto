# Proposed scanner correction · 2026-11-01

Status: **BLOCKED** for application; evaluator controls **NOT_RUN**. This is inert review material, not an installed gate and not a security approval.

The internal gate must distinguish evidence redaction from credential adjudication. A Bearer header can contain a variable reference; its authentication scheme alone does not establish an issued credential. Literal or unresolved expressions remain subject to blocking review. Independent credential signatures still take precedence. Broad evidence redaction stays intact.

The proposed patch also records path/type/errno for incomplete coverage without candidate values. Oversized files, special files, symlinks, invalid text and incomplete private-key delimiters remain unknown. It does not claim large-file coverage, general parsing of source languages, a complete SBOM, or a whole-workspace PASS.

`proposal.patch` targets the source blobs at the base commit recorded in `proposal.json`. Documentation-only descendants do not change those target blobs. The proposal is created and inspected through `ChangeGovernanceEngine.propose` / `inspect`; inspection requires independent authorization for `gates/g_security.py`. The author cannot authorize the proposal. A valid trusted signature covers the exact diff, target list, nonce and expiry. No authorization token is included. No policy, trust registry or installed engine was changed.

Independent static review identified whitespace/multiline loss, unbounded streaming/special-file risks and missing handling of incomplete private-key delimiters in earlier drafts. This version addresses those observations in text. Static review and AST parsing do not prove the implementation. The controls below and the repository's required checks must run after authorized application to an unmerged branch, before admission.

The existing source correction in this MR is distinct from this additional proposal. Publication of the proposal must not be read as proof that either source is installed or that the complete regression suite passed.

## Required controls

| Input or instrument condition | Expected disposition |
| --- | --- |
| Complete isolated variable reference in a Bearer header | No confirmed credential solely from the header scheme |
| Literal, default, concatenation, multiline or unresolved header expression | Blocking review; never silent approval |
| Independent positive credential signature anywhere, including apparent references or fixtures | Confirmed finding retained |
| Known multiline key delimiters and synthetic body | Finding with original location, no candidate value |
| Missing, orphaned, nested or mismatched key delimiters | Unknown or blocking review |
| Oversized file, growth beyond bound, unreadable/invalid input, broken link or nonregular entry | Unknown with cause and path; never a clean partial scan |
| Descriptor substitution, unavailable no-follow/nonblocking flags, concurrent modification | Explicitly test and delimit platform guarantees; unresolved observation cannot approve |
| Scanner timeout, malformed/error JSON, invalid schema or nonzero failure | No approval |
| Gitleaks finding exit with valid nonempty report | Preserve findings rather than misclassifying execution as clean |
| Empty scope or missing tools | No PASS |

Required repository validation: `python3 refuto.py selftest`, `python3 scripts/check_stdlib_only.py`, `python3 scripts/check_schemas.py`, `python3 scripts/check_wiring.py`. Tests must preserve independent positive and negative controls. Evidence-redaction patterns, exclusions and security thresholds are preserved. Bearer classification changes explicitly and its detection coverage still requires the controls above.

## External instrument controls

A separate synthetic npm lockfile contained lodash 4.17.20 and minimist 1.2.5. Syft 1.51.1 generated schema 16.1.10 with both packages. Trivy 0.69.3 recognized CVE-2021-23337 (HIGH) and CVE-2021-44906 (CRITICAL) after database initialization. A writable temporary Syft cache removed cache permission warnings. These controls validate limited instrument behavior, not this unapplied patch or global scan coverage.

The cache setting is documented by [Anchore](https://oss.anchore.com/docs/reference/syft/configuration/). A temporary cache does not change scanner coverage or install a persistent harness configuration.
