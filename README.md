## Graphene (Lightweight, Breach-Resilient and Compact Authenticated Encryption Framework for Wireless Internet of Things)

**Graphene** implements forward-secure and aggregate authenticated encryption algorithms with a focus on efficiency, offline-online techniques, and additional features such as additive homomorphism, enabling fast batch verification.

## Contents

Graphene includes the following implementations:

* [`Graphene_x86`](x86/README.md): a portable implementation on commodity hardware tailored for x86 64-bit platforms. It uses OpenSSL and GMP to implement cryptoraphic primitives and finite-field operations, respectively.

* [`Graphene_cortex_m4`](cortex-m4/README.md): an implementation on 32-bit ARM mirconcontroller: ARM Cortex-M4. It uses WolfSSL to implement both cryptographic primitives and finite-filed operations. It portable to different ARM Cortex-M microcontrollers (with or not hardware accleration peripheral), by updating the configuration file accordingly.
