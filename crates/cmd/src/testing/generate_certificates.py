#!/usr/bin/env python3
"""Generates test X.509 certificates encoded in PEM using OpenSSL."""

import itertools
import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Opts:
    alg: str
    name: str
    pkeyopt: str


def _dh_opts():
    names = (
        "dh_1024_160",
        "dh_2048_224",
        "dh_2048_256",
        "ffdhe2048",
        "ffdhe3072",
        "ffdhe4096",
        "ffdhe6144",
        "ffdhe8192",
        "modp_1536",
        "modp_2048",
        "modp_3072",
        "modp_4096",
        "modp_6144",
        "modp_8192",
    )
    return (Opts("dh", f"ffc_{name}", f"group:{name}") for name in names)


def _dsa_opts():
    bits = ((1024, 160), (2048, 224), (3072, 256))
    return (
        Opts("dsa", f"dsa_{p}", f"dsa_paramgen_bits:{p} dsa_paramgen_q_bits:{q}")
        for (p, q) in bits
    )


def _ec_opts():
    output = subprocess.check_output(
        ["openssl", "ecparam", "-list_curves"], universal_newlines=True
    )
    names = re.findall(r"(.+):", output)
    names = [name.strip() for name in names]
    return (Opts("ec", f"ecc_{name}", f"ec_paramgen_curve:{name}") for name in names)


def _edwards_opts():
    names = ("ed25519", "ed448", "x25519", "x448")
    return (Opts(name, f"ecc_{name}", "") for name in names)


def _rsa_opts():
    # XXX: Sizes larger than 8192 take a while to generate.
    n = 4
    min_bits = 1024
    return (
        Opts("rsa", f"ifc_rsa_{min_bits << i}", f"rsa_keygen_bits:{min_bits << i}")
        for i in range(n)
    )


def _rsa_pss_opts():
    # XXX: Sizes larger than 8192 take a while to generate.
    n = 4
    min_bits = 1024
    return (
        Opts(
            "rsa-pss",
            f"ifc_rsa_pss_{min_bits << i}",
            f"rsa_keygen_bits:{min_bits << i}",
        )
        for i in range(n)
    )


def generate_certificates(opts):
    """
    Generate X.509 certificates using OpenSSL.

    Args:
        opts: An iterable of Opts objects containing certificate
        generation options.

    The function generates X.509 certificates with the specified options
    and saves them in the "certificates" directory. Private keys are
    saved in the "keys" directory.

    Existing keys are skipped, and only new certificates are generated.

    The function logs the progress and any errors during the generation
    process.

    Returns:
        None
    """
    dirs = (Path("certificates"), Path("keys"))
    certificates, keys = dirs
    for dir in dirs:
        os.makedirs(dir, exist_ok=True)

    # Generate certificates for each option.
    for opt in opts:
        filename = f"{opt.name}.pem"
        if (keys / filename).exists():
            logging.debug(f"skipping: {filename}")
            continue
        try:
            logging.info(f"generating certificate: {filename}")
            command = [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                opt.alg,
                "-keyout",
                keys / filename,
                "-out",
                certificates / filename,
                "-subj",
                "/CN=Test Common Name/O=Test Organization Name",
                "-nodes",
            ]
            if opt.pkeyopt:
                command.extend(["-pkeyopt", opt.pkeyopt])
            subprocess.check_output(command, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            logging.warning(f"failed to gen-erate certificate: {filename}")
    logging.debug("deleting test private keys")
    shutil.rmtree(keys)


def main():
    opts = itertools.chain(
        _dh_opts(),
        _dsa_opts(),
        _ec_opts(),
        _edwards_opts(),
        _rsa_opts(),
        _rsa_pss_opts(),
    )
    generate_certificates(opts)


if __name__ == "__main__":
    logging.basicConfig(format="%(levelname)s: %(message)s")
    main()
