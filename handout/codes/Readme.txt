# Lab 1: Basic Cryptography - AES, RSA, and Kyber

This repository contains the implementation and analysis for **EECE5699: Computer Hardware and System Security (Lab 1)**.

## 📌 Contents
- `aes_test.c` → AES encryption timing
- `rsa_test.c` → RSA encryption timing
- `kyber_test.c` → Kyber512 (post-quantum) encryption timing
- `client_rsa.c` → Client-server secure communication with RSA
- `client_kyber.c` → Client-server secure communication with Kyber
- `benchmark.c` → Combined benchmarking (AES, RSA, Kyber)
- `plot_timings.py` → Generates comparison plots from timing data
- `makefile` → Build and run all modules
- `report.tex` → LaTeX source of lab report
- `average_comparison.png` → Final timing comparison plot
- `secret.txt` → Secret from RSA communication
- `secret_kyber.txt` → Secret from Kyber communication

## ⚡ How to Run
1. Build everything:
   ```bash
   make
