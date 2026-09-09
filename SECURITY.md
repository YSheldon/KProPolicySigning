# Signing trust boundary

Code is public. The private key is only in the production-policy-signing GitHub
environment secret KPRO_POLICY_PRIVATE_KEY_B64. No key file is checked out,
downloaded or produced by the signing code. Key use is confined to one step.

Required deployment reviewer: repository owner. Self-review is allowed; this is
explicit human approval, not independent two-person authorization. Admin bypass
is disabled. Only main is allowed to enter the environment. Main requires PRs
and policy-tests, with force-push/deletion disabled and rules applying to admins.

No pull_request_target, secret-enabled PR job, checkout of caller-provided refs,
third-party dependencies during key use, key caching or whole-workspace artifacts.
Pinned actions and dependency-free Go reduce, but do not eliminate, runner and
repository-admin trust. A repository administrator can change protection settings;
GitHub Secrets is not a non-exportable HSM. Audit settings regularly.

Profiles are fixed: maximum=0x5, low-interference=0x1, disabled=0x0. No directory
paths, grants or arbitrary bytes are accepted. Individual directory policies need
a separate privacy-preserving reviewed input design and are not implemented here.
Policies expire after one year. Receipts identify expiry and do not claim driver
acceptance; real driver validation is a separate release gate.

The key is retained for driver compatibility. Migrating an already-used key does
not erase old copies or revoke previous signatures. No internal history cleanup
or key rotation is performed by this workflow. Plan a separate rotation if the
old key's exposure history is unacceptable.
