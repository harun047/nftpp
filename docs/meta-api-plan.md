# Meta / mark API plan

Builders stay generic (`detail::make_meta_load(key, dreg)`, `detail::make_meta_set(key, sreg)`).
Everyday cases become `Rule` methods: `match_*` = load + compare, `set_*` = write.

Setting anything is always two steps: put the value in a register (`immediate`), then `meta set` / `ct set` reads it from `sreg`.

## Tier 1: build these first

| Method | nft equivalent | Expressions | Used for |
|---|---|---|---|
| `match_iifname` / `match_oifname` | `iifname "eth0"` | meta load, cmp | ✅ already exists |
| `match_mark(uint32_t mark, uint32_t mask = 0xffffffff)` | `meta mark 0x1` / `meta mark and 0xff == 0x1` | meta load, (bitwise), cmp | acting on traffic tagged earlier |
| `set_mark(uint32_t mark)` | `meta mark set 0x1` | immediate, meta set | policy routing (`ip rule fwmark`), tc |
| `set_mark_bits(uint32_t mark, uint32_t mask)` | `meta mark set meta mark and ~mask or mark` | meta load, bitwise, meta set | change only your bits; other tools share the mark |
| `save_mark()` | `ct mark set meta mark` | meta load, ct set | keep the mark on the whole connection |
| `restore_mark()` | `meta mark set ct mark` | ct load, meta set | copy the connection's mark back onto each packet |

`save_mark()` + `restore_mark()` is the usual multi-WAN / VPN pair: mark the first packet, save it to the connection, restore it on every reply so the whole flow takes the same route.

### Expression sequences

```cpp
// match_mark(mark)  (mask == 0xffffffff: skip the bitwise)
add(detail::make_meta_load(NFT_META_MARK, NFT_REG_1));
add(detail::make_cmp(NFT_REG_1, NFT_CMP_EQ, &mark, sizeof(mark)));

// match_mark(mark, mask)
uint32_t xor_val = 0;
uint32_t expected = mark & mask;
add(detail::make_meta_load(NFT_META_MARK, NFT_REG_1));
add(detail::make_bitwise(NFT_REG_1, NFT_REG_1, &mask, &xor_val, sizeof(mask)));   // reg1 = reg1 & mask
add(detail::make_cmp(NFT_REG_1, NFT_CMP_EQ, &expected, sizeof(expected)));

// set_mark(mark)
add(detail::make_immediate_data(NFT_REG_1, &mark, sizeof(mark)));
add(detail::make_meta_set(NFT_META_MARK, NFT_REG_1));

// set_mark_bits(mark, mask)   bitwise computes (reg & m) ^ x
uint32_t keep = ~mask;
uint32_t bits = mark & mask;
add(detail::make_meta_load(NFT_META_MARK, NFT_REG_1));
add(detail::make_bitwise(NFT_REG_1, NFT_REG_1, &keep, &bits, sizeof(keep)));      // clear mask bits, then set ours
add(detail::make_meta_set(NFT_META_MARK, NFT_REG_1));

// save_mark()
add(detail::make_meta_load(NFT_META_MARK, NFT_REG_1));
add(detail::make_ct_set(NFT_CT_MARK, NFT_REG_1));        // no direction: NFT_CT_MARK is Forbidden

// restore_mark()
add(detail::make_ct_load(NFT_CT_MARK, NFT_REG_1));
add(detail::make_meta_set(NFT_META_MARK, NFT_REG_1));
```

## Tier 2: add when needed

| Method | nft equivalent | Used for |
|---|---|---|
| `match_skuid(uid)` / `match_skgid(gid)` | `meta skuid 1000` | output-chain rules per user (block a user, VPN for one user) |
| `set_nftrace()` | `meta nftrace set 1` | debugging: matches show up in `nft monitor trace` |
| `match_iif(index)` / `match_oif(index)` | `iif 2` | faster than by name, but breaks when the interface is recreated (VPNs, bridges); by name is the safer default |
| `set_priority(uint32_t)` | `meta priority set 1:10` | picking a QoS / tc class |

## Internal only (private helpers, like `match_ct_state_impl`)

| Helper | nft equivalent | Why private |
|---|---|---|
| `match_l4proto(IPPROTO_TCP)` | `meta l4proto tcp` | nft adds it before `tcp dport 22`; a future `match_tcp_dport` should add it the same way |
| `match_nfproto(NFPROTO_IPV4)` | `meta nfproto ipv4` | nft adds it before `ip saddr` in `inet` tables |

## Notes

- **Mark is a plain host-order `uint32_t`**: no `htons`, `sizeof(uint32_t)`. The kernel gives no bit a meaning, but in practice it's shared as a bitmask (Kubernetes uses `0x4000`/`0x8000`; WireGuard, Tailscale and firewalld take their own bits), so prefer `set_mark_bits` when coexisting.
- **"fwmark" = packet mark (`meta mark`)**: the one `ip rule fwmark` and `tc` read. `ct mark` is per connection and routing doesn't see it until it's restored onto the packet.
- **Settable meta keys**: only `MARK`, `PRIORITY`, `PKTTYPE`, `NFTRACE` (plus special cases). The kernel rejects other keys at commit time.
- **Use the constants** (`NFT_REG_1`, `NFT_CT_MARK`), not raw numbers: `NFT_REG_1 == 1` by coincidence, `NFT_CT_MARK == 3`, and the 32-bit registers start at `NFT_REG32_00 == 8`.
