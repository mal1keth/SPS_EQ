# SPS-EQ: Structure-Preserving Signatures with Equivalence Classes

This repository implements a Structure-Preserving Signature scheme with Equivalence Classes (SPS-EQ), built using the [py_ecc](https://github.com/ethereum/py_ecc) library for elliptic curve operations.

## Overview

SPS-EQ is a cryptographic signature scheme with the following properties:

- **Structure-Preserving**: Both messages and signatures consist of group elements (no hashing to scalars)
- **Equivalence Classes**: Allows for changing the representation of a message while maintaining the validity of signatures

## Features

- Key generation (`keygen`)
- Signature generation (`sign`)
- Signature verification (`verify`)
- Representation change for messages (`chgRep`)
- Public key validation (`vKey`)

## Requirements

- Python 3.6+
- py_ecc library

## Installation

```bash
pip install py_ecc
```

## Usage

```python
from SPS_EQ import SPS_EQ

# Initialize the scheme with parameter l (number of elements in message)
l = 2
sps = SPS_EQ(l)

# Generate keys
secret_key, public_key = sps.keygen()

# Create a message
# (See example in __main__ for how to create valid messages)

# Sign a message
signature = sps.sign(message)

# Verify a signature
result = sps.verify(message, signature, public_key)

# Change representation of a message and update signature
mu = some_scalar_value  # Scalar for transformation
new_signature = sps.chgRep(message, signature, mu, public_key)
```

## Mathematical Background

The implementation uses BN128 elliptic curve pairing:
- G₁: First source group
- G₂: Second source group
- e: G₁ × G₂ → GT: Bilinear pairing function

SPS-EQ signatures maintain their validity even when messages are transformed by a scalar, preserving the mutual ratios between message elements.

## Example

The script includes a runnable example that:
1. Generates keys
2. Creates and signs a message
3. Verifies the signature
4. Demonstrates the equality property by transforming the message and updating the signature
5. Verifies the new signature on the transformed message

Run with:
```bash
python SPS_EQ.py
``` 