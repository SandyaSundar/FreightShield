"""Print a new 32-byte vault master key. Store it in a password manager/secret manager."""
import secrets

if __name__ == "__main__":
    print(secrets.token_hex(32))
