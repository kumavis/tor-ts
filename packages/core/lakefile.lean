import Lake
open Lake DSL

package «tor-core» where
  -- Lints / options can grow here as we tighten the verification surface.

require thales from git
  "https://github.com/jessealama/thales.git" @ "main"

/-- The Thales-emitted sidecars. Populated by `scripts/verify.sh` before
`lake build` is invoked; the directory exists in-tree as `Generated/`
with a `.gitkeep` so the layout is visible without committing the
generated `.lean` files. -/
@[default_target]
lean_lib Generated where
  roots := #[`Generated]

/-- Hand-written specification theorems that import the generated sidecars
and assert behavioural properties Lean checks at build time. -/
@[default_target]
lean_lib Spec where
  roots := #[`Spec]
