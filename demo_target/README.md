# Deliberately Vulnerable Demo Target

> **SECURITY WARNING**: This application is deliberately vulnerable and insecure for educational and scanning verification purposes. It binds to `127.0.0.1` (localhost) only, and **must never be exposed to an external or untrusted network**.

This standalone target application is used for local scan validation and ownership verification testing.
It serves ownership verification tokens and deliberately exhibits common misconfigurations (missing headers, insecure cookie flags, plaintext HTTP) to test scanner modules.
