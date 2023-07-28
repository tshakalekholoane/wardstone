#!/usr/bin/env python3
"""Generates test X.509 certificates encoded in PEM using OpenSSL."""

import argparse
import asyncio
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
    """
    OpenSSL command line arguments to generate private keys and
    corresponding certificates.
    """

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
    # Sizes larger than 8192 take a while to generate.
    n = 4
    min_bits = 1024
    return (
        Opts("rsa", f"ifc_rsa_{min_bits << i}", f"rsa_keygen_bits:{min_bits << i}")
        for i in range(n)
    )


def _rsa_pss_opts():
    # Sizes larger than 8192 take a while to generate.
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


async def generate_certificate(certificates, keys, opt):
    """
    Generate a single X.509 certificate using OpenSSL asynchronously.

    Args:
        opt: An Opts object containing certificate generation options.

    The function generates a single X.509 certificate with the specified
    options and saves it in the "certificates" directory. The private
    key is saved in the "keys" directory.

    An existing key is skipped, and only new certificates are generated.

    The function logs the progress and any errors during the generation
    process.

    Returns:
        None
    """
    filename = f"{opt.name}.pem"
    if (certificates / filename).exists():
        logging.debug(f"skipping: {filename}")
        return
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
        proc = await asyncio.create_subprocess_exec(
            *command, stderr=asyncio.subprocess.DEVNULL
        )
        await proc.communicate()
        if proc.returncode:
            logging.warning(f"failed to generate certificate: {filename}")
    except subprocess.SubprocessError:
        logging.warning(f"failed to generate certificate: {filename}")


async def main():
    parser = argparse.ArgumentParser(
        prog="generate_certificates",
        description="Generate test X.509 certificates encoded in PEM using OpenSSL.",
    )
    parser.add_argument(
        "-l",
        "--log-level",
        choices=["debug", "info", "warning", "error", "critical"],
        default="warning",
        help="Set the logging level (default: warning)",
    )
    arguments = parser.parse_args()

    numeric_level = getattr(logging, arguments.log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"invalid log level: {arguments.log_level}")
    logging.basicConfig(format="%(levelname)s: %(message)s", level=numeric_level)

    dirs = (Path("certificates"), Path("keys"))
    certificates, keys = dirs
    for dir in dirs:
        os.makedirs(dir, exist_ok=True)
    opts = itertools.chain(
        _dh_opts(),
        _dsa_opts(),
        _ec_opts(),
        _edwards_opts(),
        _rsa_opts(),
        _rsa_pss_opts(),
    )
    tasks = (generate_certificate(certificates, keys, opt) for opt in opts)
    await asyncio.gather(*tasks)
    logging.debug("deleting test private keys")
    shutil.rmtree(keys)


if __name__ == "__main__":
    asyncio.run(main())
