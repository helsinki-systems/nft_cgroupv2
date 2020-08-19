# nft_cgroupv2

This out-of-tree module provides `nftables` matches on hierarchical cgroup v2 structures.
Currently, `nftables` can only match cgroup IDs which is pretty pointless for modern usages.
This was developed to provide per-systemd-service firewalling.

The work is highly based on [this article](https://zasdfgbnm.github.io/2017/09/07/Extending-nftables/) and it also took some inspiration from `xt_cgroup.c` which is the cgroup v2 implementation for `xtables`.

## Building and running

1. Build this out-of-tree module according to what your distro usually does
2. Load it, e.g. using `insmod nft_cgroupv2.ko`
3. Check if it was loded using `lsmod | grep nft_cgroupv2`

You also need a patched `nftables` which was built with a patched `libnftnl`.
Patches for both are available in the [patches](patches/) directory.
Apply them in the manner your distro expects you to.
Afterwards, you can test it using `nft -f test.nft && nft list ruleset`

## How to use

Just match your cgroups ;)
See `test.nft` on examples. The `^` allows you to invert your matches, matching on all cgroups except the specified one.

## About the code

This is the first kernel module I wrote and the first time I worked with netlink.
While a lot of the heavy lifting is abstracted by some pretty nice APIs, I don't think the code looks like code produced by someone with a lot of knowledge in this field of development.
It does, however, work pretty well.
Maybe some alternative gets upstreamed at some point so we don't need this extra module anymore.
It should probably be integrated into `nft_meta` but I couldn't wrap my head around that.
