from random import randint
import time

# generate random number of n bits

    

# create a big prime generator using the miller rabin primality test with at least n digits and k tests
def miller_rabin_test(prime, base, verbose=False, indent=0):
    # write the miller and rabin test
    d = prime - 1
    s = 0
    while d % 2 == 0:
        d = d // 2
        s += 1
    if verbose: print(f"{indent * ' '}Checking if b is a witness for p")
    if verbose: print(f"{indent * ' '}p = {prime}")
    if verbose: print(f"{indent * ' '}b = {base}")
    if verbose: print(f"{indent * ' '}p-1 = 2^s * d")
    if verbose: print(f"{indent * ' '}d = {d}")
    if verbose: print(f"{indent * ' '}s = {s}")
    # p1 = (base ** d) % prime == 1
    
    if pow(base, d, prime) == 1:
        if verbose: print(f"b^d = {base}^{d} = {pow(base, d)} = {pow(base, d, prime)} mod {prime}")
        if verbose: print(f"{indent * ' '}P1 is True: b^d mod p = 1")
        return True
    #p2 = (base ** ((2 ** r) * d)) % prime == prime - 1 for some r in {0, 1, ..., s - 1}
    for r in range(s):
        if verbose: print(f"{indent * ' '}trying for r = {r}")
        if pow(base, (2 ** r) * d, prime) == prime - 1:
            if verbose: print(f"{indent * ' '}P2 is True with r={r}: b^((2^{3})*d) mod p = p - 1")
            return True
    if verbose: print(f"{indent * ' '}P1 and P2 are False")
    return False

def big_prime_generator(n, k = 10, verbose=False, indent=0, subindent_factor=4):
    maybe_prime = randint(2 ** (n - 1), 2 ** n - 1)
    if maybe_prime % 2 == 0:
        maybe_prime += 1
    count = 0
    if verbose: print(f"{indent * ' '}Attempt {count}: Trying {maybe_prime}")
    while True:
        for _ in range(k):
            base = randint(2, maybe_prime - 1)
            if verbose: print(f"{(indent+subindent_factor) * ' '}Witness {_}: {base}")
            if not miller_rabin_test(maybe_prime, base, verbose, indent=indent+subindent_factor*2):
                if verbose: print(f"{(indent+subindent_factor) * ' '}Failed with {base}")
                break
        else:
            if verbose: print(f"{(indent+subindent_factor) * ' '}Success with {maybe_prime}")
            return maybe_prime
        maybe_prime = randint(2 ** (n - 1), 2 ** n - 1)
        if maybe_prime % 2 == 0:
            maybe_prime += 1
        count += 1
        if verbose: print(f"{indent * ' '}Attempt {count}: Trying {maybe_prime}")

def egcd2(a, b):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b != 0:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return (a, x0, y0)

# define the inverse multiplicative function using euclid algorithm
def invmod(a, m):
    g, x, y = egcd2(a, m)
    if g != 1:
        return -1
    else:
        return x % m

# create a function that generates the public and private keys
def generate_keys(n=2048, k=10, verbose=False, indent=0, subindent_factor=4, filename=None):
    # if n is not an integer higher than 1024, raise an exception
    if not isinstance(n, int) or n < 1024:
        raise ValueError("n must be an integer higher than or equal to 1024")
    # write the key generation function
    if verbose: print(f"{indent * ' '}Generating p and q")
    while True:
        p = big_prime_generator(n, k, indent=indent, subindent_factor=subindent_factor, verbose=verbose)
        q = big_prime_generator(n, k, indent=indent, subindent_factor=subindent_factor, verbose=verbose)
        if verbose: print(f"{indent * ' '}p = {p}")
        if verbose: print(f"{indent * ' '}q = {q}")
        if abs(p - q) > 2 ** (n-100):  # Ensure p and q are far enough apart
            break
        if verbose: print(f"{indent * ' '}p and q are too close, trying again")
    N = p * q
    if verbose: print(f"{indent * ' '}N = p * q = {N}")
    phi = (p - 1) * (q - 1)
    if verbose: print(f"{indent * ' '}phi = (p - 1) * (q - 1) = {phi}")
    e = randint(2, phi - 1)
    while True:
        d = invmod(e, phi)
        if d != -1:
            break
        e = randint(2, phi - 1)
    if verbose: print(f"{indent * ' '}e = {e}")
    if verbose: print(f"{indent * ' '}d = {d}")
    if filename is not None:
        write_key_to_file((e, N), filename + "_public")
        write_key_to_file((d, N), filename + "_private")

    return (e, N), (d, N)

def RSA_encrypt(message, key):
    e, N = key
    # if the message is greater than N, raise an exception
    if message >= N:
        raise ValueError("Message is too long")
    return pow(message, e, N)

def encrypt_file(filename, key_filename):
    with open(filename, "rb") as file:
        message = int.from_bytes(file.read(), "big")
    e, N = read_key_from_file(key_filename)
    # if message is greater than N, raise an exception
    if message >= N:
        raise ValueError("Message is too long")
    # write the encrypted message into a file
    with open(filename + ".enc", "wb") as file:
        file.write(RSA_encrypt(message, (e, N)).to_bytes(bytes_length(N), "big"))
    
def encrypt_big_file(filename, key_filename, output_filename=None, remove_extension=False):
    e, N = read_key_from_file(key_filename)
    with open(filename, "rb") as file:
        message = int.from_bytes(file.read(), "big")
    # divide message in blocks
    if message >= N:
        blocks = []
        while message > 0:
            blocks.append(message % N)
            message = message // N
    else:
        blocks = [message]
    encrypted_blocks = [RSA_encrypt(block, (e, N)) for block in blocks]
    # rebuild a single number so that encrypting again returns the original message
    encrypted_message = sum([block * (N ** i) for i, block in enumerate(encrypted_blocks)])
    
    if output_filename is None:
        if remove_extension and filename.endswith(".enc"):
            output_filename = filename[:-4]
        else:
            output_filename = filename + ".enc"
    
    with open(output_filename, "wb") as file:
        file.write(encrypted_message.to_bytes(bytes_length(encrypted_message), "big"))

def bytes_length(number):
    return (number.bit_length() + 7) // 8

# create a function that writes a big number into a file as a binary file
def write_big_number(number, filename):
    with open(filename, "wb") as file:
        file.write(number.to_bytes(bytes_length(number), "big"))

# create a function that reads a big number from a file
def read_big_number(filename):
    with open(filename, "rb") as file:
        return int.from_bytes(file.read(), "big")

def write_key_to_file(key, filename):
    with open(filename, "wb") as file:
        e, N = key
        e_bytes = e.to_bytes(bytes_length(e), "big")
        N_bytes = N.to_bytes(bytes_length(N), "big")
        file.write(len(e_bytes).to_bytes(4, "big"))
        file.write(e_bytes)
        file.write(len(N_bytes).to_bytes(4, "big"))
        file.write(N_bytes)

def read_key_from_file(filename):
    with open(filename, "rb") as file:
        e_length = int.from_bytes(file.read(4), "big")
        e = int.from_bytes(file.read(e_length), "big")
        N_length = int.from_bytes(file.read(4), "big")
        N = int.from_bytes(file.read(N_length), "big")
        return e, N

if __name__ == "__main__":
    
    ### TO CREATE A KEY COUPLE, UNCOMMENT THIS LINES DOWN HERE AND USE APPROPRIATE FILENAMES ###
    start_time = time.time()
    public, private = generate_keys(2048, 10, verbose=True, filename="pagopa_minecraft")
    end_time = time.time()
    print(f"Time taken to generate the key: {end_time - start_time} seconds")

    ### TO ENCRYPT A FILE FOR OTHER, UNCOMMENT THIS LINES DOWN HERE AND USE APPROPRIATE FILENAMES ###
    # encrypt_big_file("messaggio.txt", "nino_public", "criptato_per_nino")

    ### TO DECRYPT A FILE SENT TO YOU, UNCOMMENT THIS LINES DOWN HERE AND USE APPROPRIATE FILENAMES ###
    # encrypt_big_file("msg_da_nino", "vito_private.key", "msg_da_nino_decriptato")

    ### MILLER-RABIN TEST
    # print(miller_rabin_test(280, 279, verbose=True))

    ### PRINT THE NUMBERS SAVED IN A KEY FILE
    # e, N = read_key_from_file("public_keys/joffrey_public.key")
    # print(f"e = {e}")
    # print()
    # print(f"N = {N}")
    