#!/usr/bin/env python

# Copyright (C) 2024 OVH SAS

import argparse
import json
import sys
from encryption import Decrypter

ROOT_KEY = b"Next-Gen Object Storage & Serverless Computing\n"

parser = argparse.ArgumentParser(description="decryption tool")
parser.add_argument("--rootkey", type=str, default=ROOT_KEY, help="root key")
parser.add_argument(
    "--metadata",
    type=str,
    default="metadata.json",
    help="path of object metadata json file",
)
parser.add_argument(
    "--account",
    type=str,
    default="AUTH_demo",
    help="name of the account in which the object is stored",
)
parser.add_argument(
    "--container",
    type=str,
    required=True,
    help="name of the container in which the object is stored",
)
parser.add_argument(
    "--obj", type=str, required=True, help="name of the object to fetch"
)
args = parser.parse_args()

# Read metadata
with open(args.metadata, "r") as infile:
    metadata = json.load(infile)

# Decrypt object
decrypter = Decrypter(
    root_key=args.rootkey,
    account=args.account,
    container=args.container,
    obj=args.obj,
    metadata=metadata,
)
decrypted_metadata = decrypter.decrypt_metadata()
with open("metadata.json", "w") as outfile:
    json.dump(decrypted_metadata, outfile)

while 1:
    chunk = sys.stdin.buffer.read()
    if not chunk:
        break
    data = decrypter.decrypt(chunk)
    sys.stdout.buffer.write(data)

ivs = decrypter.get_ivs()
with open("iv.json", "w") as outfile:
    json.dump(ivs, outfile)
