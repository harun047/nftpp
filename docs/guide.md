## Chains

A base chain, equivalent to
`nft add chain inet fw incoming '{ type filter hook input priority 0; policy drop; }'`:

```cpp
nftpp::Chain incoming{"fw", "incoming"};
incoming.make_base({"filter", NF_INET_LOCAL_IN, 0, NF_DROP});
```

A regular chain (only reached by `jump`):

```cpp
nftpp::Chain from_wan{"fw", "from_wan"};
```

New to base vs regular chains? See [concepts.md](concepts.md#base-chains-and-regular-chains).

### Attributes nftpp doesn't wrap

nftpp covers the common chain settings, not every libnftnl attribute. For
anything else, use `native_handle()` to reach the underlying `nftnl_chain`
and set it with libnftnl directly.

For example, a netdev ingress chain needs a device, equivalent to
`nft add chain netdev edge wan_in '{ type filter hook ingress device "ether1" priority -500; }'`:

```cpp
nftpp::Chain wan_in{"edge", "wan_in"};
wan_in.make_base({"filter", NF_NETDEV_INGRESS, -500, std::nullopt});

// not wrapped by nftpp: set it through libnftnl
nftnl_chain_set_str(wan_in.native_handle(), NFTNL_CHAIN_DEV, "ether1");
```

When using the native handle:

- **Don't free it.** The `Chain` still owns it and frees it in its destructor.
- **Don't change attributes nftpp manages** (name, table, type, hook,
  priority, policy). nftpp keeps its own copy of these, so `name()`,
  `base()` and friends would return stale values.
