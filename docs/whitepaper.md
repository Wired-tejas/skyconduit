# SkyConduit Technical Whitepaper: O(1) Memory Remote File Transfer Engine

## Abstract
This document outlines the architecture, constraints, and mathematical proofs governing the **SkyConduit** remote file transfer engine. Traditional engines suffer from $O(N)$ space complexity (where $N$ is file size) because they rely on intermediate disk writes or heap buffers. SkyConduit implements a true zero-buffer stream pipeline, achieving strict $O(1)$ memory boundaries.

---

## 1. Mathematical Boundary of Memory Complexity

In a standard file transfer proxy, the memory footprint $M$ can be defined as:

$$M(N) = \int_{0}^{T} R_{\text{in}}(t) \, dt - \int_{0}^{T} R_{\text{out}}(t) \, dt$$

Where:
* $R_{\text{in}}(t)$ is the incoming network ingestion rate.
* $R_{\text{out}}(t)$ is the outgoing write or upload speed.
* $N$ is the total file size.

When $R_{\text{in}}(t) > R_{\text{out}}(t)$ without a bounded pipeline, $M(N)$ scales linearly with time $T$, resulting in $O(N)$ heap consumption. 

### SkyConduit's O(1) Constraint
By utilizing Node.js stream backpressure via the high-water-mark (`highWaterMark`) parameter, SkyConduit enforces a maximum internal queue size ($C_b$):

$$M(N) = \min \left( \sum_{i=1}^{k} \text{chunk}_i, C_b \right) \approx \text{constant}$$

Since $C_b$ defaults to a static buffer limit (typically 16 KB for standard Object streams or 64 KB for Binary streams in V8), memory consumption is bounded as:

$$\lim_{N \to \infty} M(N) = C_b = O(1)$$

---

## 2. Backpressure and TCP Congestion Avoidance

Our pipeline links the reader socket (source) to the writer socket (destination). 

```text
[Source Server] ---> (Reader Socket Buffer) ---> [SkyConduit Engine] ---> (Writer Socket Buffer) ---> [Destination Server]
                               \                      /
                                \--- [Backpressure] -/