# Network Security Protocol Simulations in ns-3

This repository contains custom ns-3 simulation source files developed for networking security experiments. The scenarios focus on routing protocol behavior under malicious or invalid control-plane activity.

The code in this repository is intended to be copied into an existing ns-3 source tree and executed there. The full ns-3 framework is not included here because this repository is meant to track only the custom project code.

## Included Simulations

- `src/rip.cc`: RIP blackhole attack simulation with convergence monitoring, routing table snapshots, throughput tracking, and recovery analysis.
- `src/ospf.cc`: OSPF control-plane attack simulation using a forged LSA with incorrect MD5 authentication to test packet rejection and authentication failure handling.
- `src/isis.cc`: Simplified IS-IS simulation with fake LSP injection and HMAC-MD5-based authentication checks.

## Expected Execution Environment

These files were developed and run inside an ns-3 project based on the ns-3 GitHub distribution (`ns-3-allinone` / `ns-3-dev` style workflow).

Typical setup from the ns-3 base project is:

```bash
./download.py
./build.py --enable-examples --enable-tests
cd ns-3-dev
```

If using a released tarball version of ns-3, the usual flow is:

```bash
./build.py --enable-examples --enable-tests
cd ns-3
```

## Prerequisites

- A working ns-3 installation or ns-3 source tree
- C++ build support required by ns-3
- OpenSSL development libraries available on the system

`ospf.cc` and `isis.cc` use OpenSSL headers such as `openssl/md5.h` and `openssl/hmac.h`, so the ns-3 environment must be able to compile code that links against OpenSSL/libcrypto.

## How To Run

### 1. Copy the simulation files into ns-3

Place these files inside your ns-3 working tree, typically under the `scratch/` directory:

```bash
cp src/rip.cc /path/to/ns-3-dev/scratch/
cp src/ospf.cc /path/to/ns-3-dev/scratch/
cp src/isis.cc /path/to/ns-3-dev/scratch/
```

### 2. Build ns-3

From inside the ns-3 root directory, configure/build ns-3 as you normally do in your environment.

For recent ns-3 layouts:

```bash
./ns3 configure --enable-examples --enable-tests
./ns3 build
```

For older `waf`-based layouts:

```bash
./waf configure --enable-examples --enable-tests
./waf build
```

### 3. Execute the simulations

Run each simulation from the ns-3 root directory.

Using `./ns3`:

```bash
./ns3 run scratch/rip
./ns3 run scratch/ospf
./ns3 run "scratch/ospf --pcap=1"
./ns3 run scratch/isis
```

Using `./waf`:

```bash
./waf --run scratch/rip
./waf --run scratch/ospf
./waf --run "scratch/ospf --pcap=1"
./waf --run scratch/isis
```

## Scenario Notes

### RIP Scenario

- Topology uses 6 nodes with a malicious node acting as a blackhole attacker.
- Attack is triggered at `35s`.
- Recovery begins at `75s`.
- Total simulation time is `120s`.

Generated artifacts:

- `results/RoutingTables_Before.txt`
- `results/RoutingTables_During.txt`
- `results/RoutingTables_After.txt`
- `results/rip-convergence.csv`
- PCAP files under `results/`

### OSPF Scenario

- Simulates OSPF hello exchange and LSA handling across a small routed topology.
- An attacker injects a forged Router-LSA at `5s`.
- The forged update uses an incorrect MD5 key (`attacker-bad-key`) to test authentication failure detection.
- Total simulation time is `20s`.

Generated artifacts:

- `results/ospf-neighbors-node*.log`
- `results/ospf-lsdb-node*.log`
- `results/ospf-rt-node*.log`
- Optional PCAP captures when `pcap` is enabled

### IS-IS Scenario

- Simulates a 4-node topology with custom IS-IS hello and LSP exchange.
- Node 2 is configured as the attacker.
- A fake LSP is injected at `20s`.
- Authentication is checked using HMAC-MD5.
- Total simulation time is `60s`.

Generated artifacts:

- Console metrics summary at the end of the run
- PCAP captures with prefix `isis-v6-native`

## Repository Scope

This repository contains only the project-specific simulation files and this documentation. The full ns-3 source tree, third-party dependencies, and generated build artifacts are intentionally not included.

## Notes

- These simulations are meant for academic/security experimentation.
- Exact build behavior can vary slightly depending on the ns-3 version used in your local environment.
- If a newer ns-3 tree uses `./ns3`, prefer that workflow. If your setup is older and uses `waf`, use the `waf` commands instead.
