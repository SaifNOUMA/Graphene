## Graphene (Lightweight, Breach-Resilient and Compact Authenticated Encryption Framework for Wireless Internet of Things)

**Graphene_x64** contains:

* [`Graphene_prf`](prf): implements a pseudo-random functions for finite-field numbers and fine strings. 
* [`Graphene_umac`](umac): implements the universal MACs, used in Graphene, namely Linear Congruential MAC and Square Hash MAC algorithms. 
* [`Graphene_test`](test): test files for encryption and MAC algorithms using different libraries.
* [`Graphene_bench`](bench): bench files for crypgraphic primitives and propsoed MAC schemes.
* [`Graphene_authenc`](authenc): bench files for the proposed authenticated encryption algorithms.

To compile the source files in a given folder, execute the following command from the command prompt:

```sh
$ make
```
