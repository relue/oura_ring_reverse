#!/usr/bin/env python3
"""Decrypt all Oura PyTorch models using the embedded AES-256-GCM key."""

from Crypto.Cipher import AES
import base64
import os
from pathlib import Path

# Keys from secrets.json (embedded in APK)
KEYS = {
    "2f1f19fb-f0f5-4cc3-9aeb-0591cb666ea0": "kmElv6o7FUVdIB5/7+e1yrkIz27ojzfJ1CwZPTvTfpg=",
    "13e4f41f-5882-4dab-805f-f5c71022222a": "awpYSTsifG1F0PUBnx6hYPfgvuRjhNEsvY6EkwneiaU=",
}

# Current active key (from PyTorchModelType.java)
CURRENT_KEY_LABEL = "2f1f19fb-f0f5-4cc3-9aeb-0591cb666ea0"
KEY = base64.b64decode(KEYS[CURRENT_KEY_LABEL])

def decrypt_oura_model(encrypted_path: str, output_path: str) -> bool:
    """
    Decrypt an Oura PyTorch model (.pt.enc -> .pt)

    File format: [12-byte IV][ciphertext][16-byte GCM tag]
    """
    try:
        with open(encrypted_path, 'rb') as f:
            data = f.read()

        # Parse file format
        iv = data[:12]
        ciphertext_with_tag = data[12:]
        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]

        # Decrypt using AES-GCM
        cipher = AES.new(KEY, AES.MODE_GCM, nonce=iv)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)

        with open(output_path, 'wb') as f:
            f.write(decrypted)

        return True
    except Exception as e:
        print(f"  ERROR: {e}")
        return False

def main():
    # Paths
    encrypted_dir = Path("/home/witcher/projects/oura_ring_reverse/_large_files/models/assets")
    output_dir = Path("/home/witcher/projects/oura_ring_reverse/native_parser/decrypted_models")

    # Find all encrypted models
    encrypted_files = list(encrypted_dir.rglob("*.pt.enc"))

    print(f"Found {len(encrypted_files)} encrypted models")
    print(f"Output directory: {output_dir}\n")

    success = 0
    failed = 0
    skipped = 0

    for enc_file in sorted(encrypted_files):
        # Determine output path (flatten protected/ subdirectory)
        output_name = enc_file.stem  # removes .enc
        if not output_name.endswith('.pt'):
            output_name = enc_file.name.replace('.pt.enc', '.pt')
        output_path = output_dir / output_name

        # Check if already decrypted
        if output_path.exists():
            print(f"[SKIP] {enc_file.name} (already exists)")
            skipped += 1
            continue

        print(f"[DECRYPT] {enc_file.name} -> {output_name}")
        if decrypt_oura_model(str(enc_file), str(output_path)):
            size_kb = output_path.stat().st_size / 1024
            print(f"  OK ({size_kb:.1f} KB)")
            success += 1
        else:
            failed += 1

    print(f"\nSummary: {success} decrypted, {skipped} skipped, {failed} failed")

if __name__ == "__main__":
    main()
