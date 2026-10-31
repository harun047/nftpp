## Coverage

nftpp wraps the common path, not all of libnftnl.

- A libnftnl attribute gets a wrapper when a real use case needs it.
- Everything else stays reachable through native_handle().
- Rules for native_handle() users:
  - don't free the handle (the wrapper owns it)
  - don't change attributes the wrapper manages (e.g. NFTNL_CHAIN_NAME),
    or the wrapper's cached values (name(), table()) go stale

## Expr is move-only

Copy is deleted (assignment and constructor). This is because a shallow copy will lead to two owners of one nftnl_expr\* and inevitably a double free. Move transfers ownership and sets the source to null

## Expr(nftnl_expr\*) is explicit

This prevents a hidden temporary Expr class from taking ownership and later freeing the raw nftnl_expr pointer that the caller still uses... leads to a use after free or double free

# Builders live in a private header

Builders live in the src/ which is PRIVATE in cmake include directives and users cannot depend on them
