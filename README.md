# PSP Integration into VPP on Marvell OCTEON (VPP Plugin)


---



## Overview

This project integrates **PSP (Packet Security Protocol)** directly into the VPP (Vector Packet Processing) pipeline as a plugin, adding **encryption** and **decryption** stages that run inside the data plane. It targets high‑throughput, low‑latency scenarios—e.g., data centers and cloud fabrics on a **Marvell OCTEON** DPU—where user‑space crypto can become a bottleneck.  
---

## What this plugin does

- Adds **two VPP graph nodes**:
  - `psp-encrypt`: encrypts UDP payload inline with **AES‑GCM**, appends a PSP trailer (ICV/tag), and updates IP/UDP lengths/checksums. Registered on the **`device-output`** arc.  
  - `psp-decrypt`: authenticates and decrypts PSP packets, removes PSP overhead, and restores the original IP/UDP packet. Registered on the **`device-input`** arc. 
- Uses OpenSSL **EVP** and **CMAC** APIs for AES‑GCM and key derivation (software path today; future‑proof for offload). 
- The PSP header/trailer layout and helper constants are defined in `psp.h` (e.g., `PSP_ICV_OCTETS`, `PSP_CRYPT_OFFSET_UNITS`, `psp_hdr`, `psp_trailer`). 

 

---

## Repository layout

```
.
├── CMakeLists.txt        # Registers the plugin with VPP build using add_vpp_plugin(psp …) 
├── psp.h                 # PSP header/trailer, network headers, constants, checksum decls
├── psp_enc_node.c        # "psp-encrypt" node (device-output arc)
└── psp_dec_node.c        # "psp-decrypt" node (device-input arc)
```

- **CMakeLists.txt** uses `add_vpp_plugin(psp …)` and lists the two node sources and exported header.  
- **psp.h** declares `struct psp_hdr`, `struct psp_trailer` (ICV), crypt‑offset units, and related network structures/macros.   
- **psp_enc_node.c** registers `psp-encrypt` and attaches it as a **device‑output** feature (`runs_before = "interface-output"`). 
- **psp_dec_node.c** registers `psp-decrypt` and attaches it as a **device‑input** feature (`runs_before = "ip4-unicast","ip6-unicast"`). 

---

## Build & install

### Prerequisites

- A VPP development/build tree (plugin is intended to live under `vpp/src/plugins/psp/`) and CMake ≥ **3.16**. 
- **OpenSSL** development headers/libs (required by `find_package(OpenSSL REQUIRED)`). 

### Steps 

1. Create the plugin directory and add the sources:
   ```
   vpp/src/plugins/psp/
     ├─ CMakeLists.txt
     ├─ psp.h
     ├─ psp_enc_node.c
     └─ psp_dec_node.c
   ```
2. Build VPP (standard VPP build). The plugin shared object (`*.so`) will be produced under VPP’s build‑root alongside other plugins 
 

---

## Enable in VPP

### Via `startup.conf`

Add an entry to enable the plugin at start 

```conf
plugin psp_plugin.so { enable }
```

Then start VPP with that `startup.conf`.  

### Feature placement (what the code registers)

- **Encrypt** node: `psp-encrypt` on **device-output** arc, scheduled before `"interface-output"`.   
- **Decrypt** node: `psp-decrypt` on **device-input** arc, scheduled before `"ip4-unicast"` and `"ip6-unicast"`. 

> Because the nodes are registered as **VNET features**, you attach them at the device input/output arcs (the exact CLI to toggle features depends on your VPP build and feature plumbing). The registration points and `runs_before` ordering are in the source above. 

---

## How it works 

### PSP header & constants

`psp.h` defines the PSP header (`psp_hdr`), ICV (`psp_icv`), trailer (`psp_trailer`), crypt‑offset units (`PSP_CRYPT_OFFSET_UNITS = 4`), ICV length (`PSP_ICV_OCTETS = 16`), header ext‑len units (`PSP_HDR_EXT_LEN_UNITS = 8`), version/flags packing, and a 64‑bit `HTONLL` helper. It also declares checksum helpers for IPv4/IPv6 UDP. 

### Encrypt path (`psp-encrypt`)

- Checks Ethertype (IPv4/IPv6), ensures L4 is UDP, computes payload length, and makes room for PSP header + ICV using `memmove`.  
- Builds a **PSP header** with:
  - `next_hdr = UDP`, `hdr_ext_len` (with/without VC), `crypt_off` (in 4‑byte units), version/flags, `spi`, and a **monotonic 64‑bit IV counter** (network order).  
- Derives a per‑packet key using **CMAC** helpers (`derive_psp_key_*`), then performs **AES‑GCM** with OpenSSL EVP:
  - AAD = PSP header + any cleartext bytes up to `crypt_off`
  - CT = UDP payload (beyond any cleartext offset)
  - Tag size = 16 bytes (ICV)  
- Writes back new **IP/UDP lengths** and recomputes checksums; expands buffer length by PSP overhead. 

### Decrypt path (`psp-decrypt`)

- Validates Ethertype/L4, parses PSP header, computes overhead and crypt offset.   
- Reconstructs the 12‑byte IV as `{ SPI (4B) || IV (8B) }`, derives the same key, and runs **AES‑GCM** decrypt with AAD identical to the encrypt path.   
- On success, removes PSP header/trailer, restores payload, shrinks **IP/UDP lengths**, and recomputes checksums. 



---

## Configuration knobs & limitations

- **Config structure**: Both nodes use a static `psp_cfg` with fields like `master_key0/1`, `spi`, `crypto_alg` (AES‑GCM‑128/256), `crypt_offset`, and `include_vc`. Runtime CLI/API to set these is **not implemented yet**—you currently configure them in code.   
- **Software crypto**: Implementation uses OpenSSL in software today; the report flags **hardware offload** on OCTEON as future work. 
- **Error handling & cfg**: The report lists “add error handling and runtime configuration” as an area to improve. 

---

## Testing outline

The report proposes a pragmatic test plan you can reuse:

- **Traffic generation** with `iperf3` over TAP/AF_PACKET, varying packet sizes (64B–1500B) and long runs.  
- **Throughput** comparison with/without PSP to quantify overhead; aim for minimal degradation.  
- **Stability under load** (target line‑rate up to 10 Gbps), watching for drops or faults.  
- **CPU utilization** vs AES‑GCM‑128/256 to size deployments.  


---



## Credits & contributions (two major contributors)

As documented in the report, this work was completed by **two major contributors**:

- **Chalasani Vineeth (IIT Hyderabad)** — VPP environment setup, PSP encryption node, CMake integration. 
- **Sanskriti Agarwal (IIT Hyderabad)** — PSP decryption node, debugging, documentation/blog. 



---




