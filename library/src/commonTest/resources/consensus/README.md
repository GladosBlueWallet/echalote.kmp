Offline fixtures for ConsensusSignatureTest / ConsensusFetchVerifyTest.

- consensus-microdesc-2026-10-22-0200.z: zlib of the microdesc consensus served by moria1
  (http://128.31.0.39:9231/tor/status-vote/current/consensus-microdesc), valid-after
  2026-10-22 02:00:00 UTC, valid-until 05:00:00 UTC. 8 of 9 authorities signed (no bastet).
- authority-keys-all-2026-10-22.txt: http://128.31.0.39:9231/tor/keys/all at the same time
  (17 certs, including expired certs and certs of retired, unpinned authorities).
- synthetic-*.txt: certificates for a throwaway test authority (2048-bit keys made with
  openssl for these tests only; private keys were not kept). published 2026-01-01,
  expires 2027-01-01, fingerprint C8313F0A407F1D7EE95F93D2F9D7D1D7EDD78583.
  - good: valid.
  - bad-crosscert: certification valid, cross-cert signs the wrong digest.
  - forged-certification: certification signed by an unrelated key.
