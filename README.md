# snort3 build for ASUS-Merlin firmware and Entware

## Background
Inspired by the work done by [faux123](https://github.com/faux123/snort3), I decided
to update to the latest that is included in the updated main branch of Entware.
There are many reasons why this isn't built as part of the current Entware repository,
but mainly, if you want `afpacket` for packet monitoring, you have to compile against
a kernel version of 3.14+. The current version of Entware for the ASUS architecture
(aarch64) is based around kernel 3.10.x. Why do you care about `afpacket`? `afpacket` tends to have better
performance and less issues with packets dropping up until you get to
around 10G connections, and then, it becomes a dead heat with `pcap`. For most of us,
We are rocking 1G fiber at the top end, so `afpacket` works great for us, and we need that
little extra performance on these more resource constrained embedded devices.

Knowing that we can [cross compile](https://github.com/crosstool-ng/crosstool-ng) for 4.1.49,
and that at least on my AX11000 we have a 4.1.51 kernel running, I did some modifications to
configure Entware for just this type of setup.

---

**BEWARE!** This only works on a device with a newer 4.1+ kernel on the proper architecture. Please double check to make sure your device is compatible.
To check your device for your kernel version and architecture:
- ssh or telnet into your router
- issue the command: `uname -rm`
  - you should see something like this: `4.1.51 aarch64`

---

## How to install it?

- Download all the packages to your router from the current Release
    - The one exception here may be libopenssl_3 packages. If you can, update from the official
    Entware repository before trying this one.
- You'll need to modify your `/opt/etc/opkf.conf` to add `aarch64-4.1` as a valid architecture to be able to install these packages
    - Add the following line at the end of your opkg.conf: `arch aarch64-4.1 200` and save
- Install using opkg in this order:
    - libopenssl_3* (skip these if you already upgraded from the Entware repo)
    - libpciaccess
    - libhwloc
    - libtirpc
    - libdaq3
    - snort3
- Follow the rest of the [directions from faux123](https://www.snbforums.com/threads/experimental-snort3-ids-ips-on-asusmerlin-ac86-ax88-routers-only.66123/) on SmallNetBuilder

---
**UNTESTED**
You can try to use the `snort_manager.sh` script to do the install

```
mkdir -p /jffs/addons/snort 2>/dev/null
curl --retry 3 "https://raw.githubusercontent.com/linuxbozo/snort3-merlin/main/snort_manager.sh" -o "/jffs/addons/snort/snort_manager.sh" && chmod 755 "/jffs/addons/snort/snort_manager.sh" && /jffs/addons/snort/snort_manager.sh install
```
---

## How did you build these?
The step by step is laid out in the GitHub Action workflow, which you can view as part of this repo in case you want to replicate how I'm doing this. The basics:
- Have a linux machine
- Checking out this repo
- Checking out the [Entware/Entware](https://github.com/Entware/Entware) repo
- Making sure I have all the necessary build tools installed to build the cross compiler (`build-essential`, etc)
- Modify the Entware source to enable `aarch64-4.1` as a valid architecture by copying in the contents of this repos `aarch64-4.1` directory
- Run `make package/symlinks` to get Entware to download all the packages source from various GitHub repos, like [entware-packages](https://github.com/Entware/entware-packages)
- Make sure Entware is configured to use the `aarch64-4.1` .config
- Build the cross compiler tools and toolchain (gcc, etc)
- Modify some of the packages source code to use the hard coded `/opt` path that Entware uses instead of `/` or `/usr`
- Build all the various packages using their specific package/compile target
