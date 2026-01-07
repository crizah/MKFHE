# MKHFE – SageMath Experimental Evaluation Code

This repository contains the **SageMath implementation used to generate the experimental results** for a research paper on **Multi‑Key Homomorphic Functional Encryption (MKHFE)**.

The code reproduces the cryptographic setup, key generation, encryption, decryption, homomorphic operations, and performance measurements reported in the paper.

---

## Overview

The implementation follows an **RLWE-based MKHFE construction** over the cyclotomic ring:
  ```
Z_q[x] / (Φ_m(x))
  ```
Multiple clients participate in key generation and partial decryption, coordinated by a central server. The server **does not learn secret keys or plaintexts** and only aggregates protocol messages. The network is setup in such a way where the server broadcasts to all subscribers (clients) and receives individual packages from the clients.

The code is **not optimized** and is intended **only for experimental evaluation**, not production or real-world deployment.

---

## Repository Structure

```
.
├── client.sage   # Client-side MKHFE operations (run by multiple clients)
├── server.sage   # Server-side coordination and aggregation
├── MKFHE.sage   # Combined file 
└── README.md

```

---

## Cryptographic Parameters

Defined identically on both client and server:

* Security parameter: `λ = 84`
* Cyclotomic index: `m = 1024`
* Ring dimension: `n = φ(m)`
* Modulus: `q = 12289`
* Plaintext modulus: `t = 2`
* Noise distribution: uniform in `[-3, 3]`
* Ring:

  ```
  Rq = Z_q[x] / (Φ_m(x))
  ```

These parameters match those used in the paper for benchmarking.

---
## Protocol Overview

### Server (`server.sage`)

The server:

* Generates global public parameters `(a*, B_list)`
* Samples error polynomials `e_list`
* Collects public keys from all clients
* Broadcasts:

  * Combined public keys
  * Partial decryption keys
  * Auxiliary keys (R1, R2)

The server **never performs decryption** and does not possess any secret keys.

---

### Client (`client.sage`)

Each client:

* Generates its own secret key `s_i`
* Computes its public key `pk_i`
* Participates in:

  * Group public key generation
  * Encryption
  * Partial decryption
  * Auxiliary key generation
  * Relinearization key generation

Each client independently measures:

* Encryption time
* Decryption time
* Addition time
* Multiplication (with relinearization) time

---

# Network Model

The experimental setup follows a centralized coordinator with multiple clients communication model, implemented using TCP sockets. This network layer is not part of the MKHFE cryptographic construction and is used solely to coordinate protocol rounds and collect performance measurements.

## Roles

### Server (server.sage)
* Acts as a coordination entity.
* Generates and distributes public system parameters (a*, B_list) and sampled error polynomials (e_list).
* Collects public keys, partial decryption keys, and auxiliary keys from all clients.
* Broadcasts aggregated values back to all participants once all expected inputs are received.
* The server waits until all clients submit a given artifact (e.g., public keys, partial decryption keys, auxiliary keys) before broadcasting the combined result.

### Clients (client.sage)
* The number of clients (k) is fixed and known in advance.
* Each client represents a single MKHFE participant.
* Independently generates its secret key and corresponding public key.
* Performs encryption, partial decryption, auxiliary key generation, and final decryption locally.
* Participates in homomorphic evaluation after receiving the relinearization key.

## Communication Pattern
* Communication uses persistent TCP connections.
* Messages are serialized using Python pickle and sent with a 4-byte length prefix to ensure correct message framing.
* The server spawns one thread per client and uses synchronization primitives to safely collect client submissions.
  
---

## Performance Measurements

The following operations are benchmarked:

* Encryption
* Decryption
* Homomorphic addition
* Homomorphic multiplication (with RLK)

Each operation is measured using:

* Fixed iteration count (1,000,000 operations)
* Time-based throughput (operations per minute)

Timing is performed using Python’s `time` module.

The experiment was conducted with ec2 instances with 3 clients and 1 server with the insatnce having the following specifications:

Storage: 30GiB
OS:  Ubuntu, 24.04, 64 bit (x86) architecture 
Virtual server type: t2.micro , 1 CPUs
run with SageMath version 9.4 for Ubuntu 20.04 64 bit(x86) and Python 3.12

# Results:

## For 1 million operatiosn of a specific kind:
* Addition: 5.2715 seconds
* Encryption: 38.3184 seconds
* Multiplication: 108.9109
* Decryption: 13.7772

## Number of Operations ran in 60 seconds
* Addition: 11385199
* Encryption: 1566170
* Multiplication: 550458
* Decryption: 4357298

---

## How to Run

### Requirements

* SageMath (tested with SageMath ≥ 9.4)
* Python standard libraries (socket, threading, pickle)

### Steps

1. Start the server:

   ```bash
   sage server.sage
   ```

2. Start **multiple clients** (number must match `ALLOWED_CLIENTS` on server):

   ```bash
   sage client.sage
   ```

Each client must run in a separate process.

---

## Notes & Limitations

* This code is **for research and benchmarking only**
* No constant-time guarantees
* Network communication is unencrypted
* Network latency, serialization cost, and socket overhead are excluded from performance measurements.

---

## Reproducibility

All parameters are fixed and deterministic except for:

* Noise sampling
* Random key generation

Multiple runs were averaged when reporting results in the paper.

---

## License

This code is provided for **academic and research use only**.

