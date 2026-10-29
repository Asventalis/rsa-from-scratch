# Toy RSA Implementation

RSA written from scratch in Python to understand the algorithm: random odd candidates of n bits are tested with the Miller-Rabin probabilistic primality test (k rounds), the key pair (e, N) / (d, N) is built from phi(N) with the extended Euclidean algorithm for the modular inverse, and files are encrypted/decrypted with modular exponentiation (`pow(m, e, N)`). Messages larger than N are split into base-N blocks so arbitrary files can be processed, and keys are serialised to a simple length-prefixed binary format.

## How to run
Python 3, standard library only. Edit the `__main__` block of `my_RSA.py`: `generate_keys(2048, 10, filename="name")` writes `name_public` / `name_private`; `encrypt_big_file("msg.txt", "friend_public", "out.enc")` encrypts and the same call with the private key decrypts.

## Notes
- For learning only, not secure: no padding (textbook RSA), `random.randint` is not a cryptographic RNG, e is chosen at random, and the block scheme leaks structure.
- The key files and the exchanged messages are not included in the repository.
