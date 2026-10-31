## Scope

nftpp is **not** a complete wrapper of libnftnl. It covers what most
firewall and NAT setups need:

- tables, base and regular chains
- rules built from common expressions (payload, meta, ct, cmp, bitwise,
  immediate, nat, masquerade, limit)
- atomic batches

Anything nftpp doesn't wrap is still reachable: every object exposes its
underlying libnftnl handle, so you can set extra attributes with libnftnl
directly (see "Escape hatch" below).

Missing something you need? Open an issue — coverage grows with real use cases.
