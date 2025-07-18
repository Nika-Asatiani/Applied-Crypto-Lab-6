from binascii import unhexlify, hexlify
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16  # AES block size is 16 bytes
KEY = b"this_is_16_bytes"

# Ciphertext = IV + encrypted blocks (from check_decrypt.py success)
CIPHERTEXT_HEX = (
    "746869735f69735f31365f6279746573"
    "9404628dcdf3f003482b3b0648bd920b"
    "3f60e13e89fa6950d3340adbbbb41c12"
    "b3d1d97ef97860e9df7ec0d31d13839a"
    "e17b3be8f69921a07627021af16430e1"
)


# This is the given padding oracle function - it tells us if padding is correct
def padding_oracle(ciphertext: bytes) -> bool:
    """Returns True if the ciphertext decrypts with valid padding, False otherwise."""
    if len(ciphertext) % BLOCK_SIZE != 0:
        return False
    try:
        iv = ciphertext[:BLOCK_SIZE]
        ct = ciphertext[BLOCK_SIZE:]
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        unpadder.update(decrypted)
        unpadder.finalize()
        return True
    except (ValueError, TypeError):
        return False


# TASK 2: Block Splitting - This function cuts data into 16-byte pieces
def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]:
    """Split data into blocks of the specified size."""
    # Make empty list for blocks
    blocks = []

    # Go through data in steps of 16 bytes
    for i in range(0, len(data), block_size):
        # Take 16 bytes
        block = data[i:i + block_size]

        # Only keep complete blocks (exactly 16 bytes)
        if len(block) == block_size:
            blocks.append(block)

    return blocks


# TASK 3: Single Block Decryption - This is the main attack function
def decrypt_block(prev_block: bytes, target_block: bytes) -> bytes:
    """
    Decrypt a single block using the padding oracle attack.
    This function finds the secret text in one block.
    """
    print(f"[*] Attacking block: {target_block.hex()}")

    # This will store the middle values (after AES but before XOR)
    intermediate = bytearray(BLOCK_SIZE)

    # Attack each byte from right to left (byte 15, 14, 13, ..., 0)
    for pos in range(BLOCK_SIZE - 1, -1, -1):
        print(f"[*] Working on byte {pos}")

        # We want different padding values: 1, 2, 3, etc.
        padding_value = BLOCK_SIZE - pos
        print(f"[*] Want padding value: {padding_value}")

        # Make a fake previous block to trick the system
        fake_prev = bytearray(BLOCK_SIZE)

        # Set bytes we already found to make correct padding
        for i in range(pos + 1, BLOCK_SIZE):
            fake_prev[i] = intermediate[i] ^ padding_value

        # Try all possible values (0 to 255) for this byte
        found = False
        for guess in range(256):
            # Put our guess in the fake block
            fake_prev[pos] = guess

            # Make test data: fake_prev + target_block
            test_data = bytes(fake_prev) + target_block

            # Ask the oracle: is this padding correct?
            if padding_oracle(test_data):
                # Yes! We found the right value
                # The middle value is: guess XOR padding_value
                intermediate[pos] = guess ^ padding_value
                print(f"[+] Found byte {pos} = {intermediate[pos]:02x}")
                found = True
                break

        if not found:
            raise Exception(f"Could not find byte at position {pos}")

    # Now get the real text: middle_value XOR real_previous_block
    plaintext = bytearray(BLOCK_SIZE)
    for i in range(BLOCK_SIZE):
        plaintext[i] = intermediate[i] ^ prev_block[i]

    print(f"[+] Block decrypted: {bytes(plaintext).hex()}")
    return bytes(plaintext)


# TASK 4: Full Attack - This attacks all blocks in the message
def padding_oracle_attack(ciphertext: bytes) -> bytes:
    """Attack the whole message block by block."""
    print("[*] Starting full attack...")

    # Cut the message into blocks
    blocks = split_blocks(ciphertext)
    print(f"[*] Found {len(blocks)} blocks")

    # First block is the IV (starting value)
    iv = blocks[0]
    # Other blocks are the secret message
    secret_blocks = blocks[1:]

    print(f"[*] IV: {iv.hex()}")
    print(f"[*] Secret blocks: {len(secret_blocks)}")

    # List to save decrypted blocks
    decrypted_blocks = []

    # Attack each secret block
    for i, block in enumerate(secret_blocks):
        print(f"\n[*] Attacking block {i + 1}/{len(secret_blocks)}")

        # Find the previous block
        # For first block, use IV
        # For other blocks, use previous secret block
        if i == 0:
            prev_block = iv
        else:
            prev_block = secret_blocks[i - 1]

        # Attack this block
        decrypted_block = decrypt_block(prev_block, block)
        decrypted_blocks.append(decrypted_block)

    # Put all decrypted blocks together
    full_plaintext = b''.join(decrypted_blocks)
    print(f"[*] Total decrypted bytes: {len(full_plaintext)}")

    return full_plaintext


# TASK 5: Plaintext Decoding - This cleans up the final text
def unpad_and_decode(plaintext: bytes) -> str:
    """Remove padding and make text readable."""
    try:
        # Remove padding bytes
        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        clean_text = unpadder.update(plaintext) + unpadder.finalize()

        # Make it readable text
        readable = clean_text.decode('utf-8')
        return readable

    except Exception as e:
        print(f"[!] Problem removing padding: {e}")

        # Try without removing padding
        try:
            return plaintext.decode('utf-8', errors='ignore')
        except:
            # Show raw bytes if nothing works
            return f"Raw bytes: {plaintext.hex()}"


# MAIN EXECUTION - This runs the complete attack
if __name__ == "__main__":
    try:
        # Convert hex string to bytes
        ciphertext = unhexlify(CIPHERTEXT_HEX)
        print(f"[*] Message length: {len(ciphertext)} bytes")
        print(f"[*] IV: {ciphertext[:BLOCK_SIZE].hex()}")

        # Run the attack
        recovered = padding_oracle_attack(ciphertext)
        print("\n[+] Attack finished!")
        print(f"Recovered bytes: {recovered}")
        print(f"Hex: {recovered.hex()}")

        # Make it readable
        decoded = unpad_and_decode(recovered)
        print("\nFinal message:")
        print(decoded)

    except Exception as e:
        print(f"\nError: {e}")
        import traceback

        traceback.print_exc()