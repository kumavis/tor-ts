import Lake
open Lake DSL

package «tor-core» where
  -- Lints / options can grow here as we tighten the verification surface.

-- Pinned to a specific Thales commit. To bump:
--   1. Update the SHA below.
--   2. Run `bash packages/core/scripts/verify.sh` (regenerates lake-manifest.json).
--   3. Update THALES_REV in scripts/verify.sh and the CI cache key.
require thales from git
  "https://github.com/jessealama/thales.git" @ "31f300449ea4514e1975fa559011d18793ee1a7a"

/-- The Thales-emitted sidecars. Populated by `scripts/verify.sh` before
`lake build` is invoked; the directory exists in-tree as `Generated/`
with a `.gitkeep` so the layout is visible without committing the
generated `.lean` files. -/
@[default_target]
lean_lib Generated where
  globs := #[.submodules `Generated]

/-- Hand-written specification theorems that import the generated sidecars
and assert behavioural properties Lean checks at build time. -/
@[default_target]
lean_lib Spec where
  globs := #[.submodules `Spec]
