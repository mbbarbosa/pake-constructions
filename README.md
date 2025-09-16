# chic-pake
Implementation of the CHIC PAKE protocol [AsiaCrypt'2024]

The `c/chic` subfolder contains C implementations based on the CRYSTALS-KYBER development.
Make sure to `git submodule init` before trying to run `make`.
At the moment the following C implementations are available:

- `ref`: a reference implementation

Disclaimer: These implementations are not claimed to be fit for practical deployment.
In particular, no attempt has been made to ensure that the implementation of the half-ideal-cipher is constant-time with respect to the input password.
