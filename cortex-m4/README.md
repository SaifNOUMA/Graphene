## Graphene (Lightweight, Breach-Resilient and Compact Authenticated Encryption Framework for Wireless Internet of Things)

**Graphene_cortex_m4** contains:

* [`wolfSSL.I-CUBE-wolfSSL_conf.h`]: configuration file where the STM32F439ZI is selected where the hardware acceleration is enabled. 
* [`benchmark.c`]: modified benchmark files of WolfSSL to implement the proposed universal MACs and authenticated encryption algorithms. 

To compile and run, follow the instructions at [WolfSSL documentation](https://github.com/wolfSSL/wolfssl/tree/master/IDE/STM32Cube) and update the above configuration and benchmark files. 