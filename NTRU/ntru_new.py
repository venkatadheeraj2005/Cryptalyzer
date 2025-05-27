import time
import numpy as np
from logger_new import logger
from NTRUencrypt_new import NTRUencrypt
from NTRUdecrypt_new import NTRUdecrypt
from utils import factor_int


# Constants for N, p, q, df, dg, d parameter sets
PARAM_SETS = {
    "moderate": {"N": 251, "p": 3, "q": 2048, "df": 72, "dg": 72, "d": 8},  # ~128-bit security
    "high": {"N": 347, "p": 3, "q": 4096, "df": 114, "dg": 114, "d": 10},  # ~256-bit security
    "highest": {"N": 587, "p": 3, "q": 8192, "df": 196, "dg": 196, "d": 12},  # ~512-bit security
    }

def generate_keys(name: str = "key", mode: str = "highest", skip_check: bool = False, debug: bool = False,
                  check_time: bool = False) -> None:
    
    if mode not in PARAM_SETS:
        raise ValueError("Mode must be 'moderate', 'high', or 'highest'")

    params = PARAM_SETS[mode]
    #if debug:
     #   logger.info("Starting key generation in %s mode", mode)

    N1 = NTRUdecrypt(logger, debug=debug, check_time=check_time)
    N1.setNpq(**params)

    start_time = time.time() if check_time else None
    step_start = time.time() if check_time else None
    #logger.info("Generating public and private keys")
    N1.genPubPriv(name)
    if check_time:
        elapsed = time.time() - step_start
        logger.info(f"Key generation took {elapsed:.4f} seconds")

    #if skip_check:
    #   logger.info("Skipping security check")
    #else:
    #   logger.info("Performing security check on generated keys")
    #  step_start = time.time() if check_time else None
    #     logger.info("Security check passed")
    #    if check_time:
    #       elapsed = time.time() - step_start
    #      logger.info(f"Security check took {elapsed:.4f} seconds")
    #    else:
    #       logger.warning("Security check failed!")
    #
    #       if attack_simulation(N1):
    #          logger.info("Security 2 check passed")
    #         if check_time:
    #            elapsed = time.time() - step_start
    #           logger.info(f"Security check 2 took {elapsed:.4f} seconds")
    #  else:
    #
    #if check_time:
    #   total_elapsed = time.time() - start_time
    #  logger.info(f"Total key generation process took {total_elapsed:.4f} seconds")


def security_check(N1: NTRUdecrypt) -> bool:
    """
    Perform a security check by factoring NTRU parameters and verifying key strength.

    :param N1: the NTRUdecrypt object containing the parameters
    :return: True if the key passes security checks, False otherwise
    """
    factors = factor_int(N1.h[-1])
    possible_keys = (2 ** N1.df * (N1.df + 1) ** 2 *
                     2 ** N1.dg * (N1.dg + 1) *
                     2 ** N1.dr * (N1.dr + 1))

    #logger.debug("Factors of the last parameter: %s", factors)
    #logger.debug("Calculated possible keys: %d", possible_keys)

    return len(factors) == 0 and possible_keys > 2 ** 80


def encrypt(name: str, message: str, check_time: bool = False) -> str:
    """
    Encrypt a message using the public key.

    :param name: name of the key file
    :param message: plaintext message to encrypt
    :param check_time: whether to log the duration of the encryption process
    :return: encrypted message
    """
    logger.info("Encrypting message with key: %s", name)
    start_time = time.time()

    E = NTRUencrypt()
    E.readPub(f"{name}.pub")
    E.encryptString(message)

    if check_time:
        elapsed = time.time() - start_time
        logger.info(f"Encryption took {elapsed:.4f} seconds")

    return E.Me


def decrypt(name: str, cipher: str, check_time: bool = False) -> str:
    """
    Decrypt a message using the private key.

    :param name: name of the key file
    :param cipher: encrypted message to decrypt
    :param check_time: whether to log the duration of the decryption process
    :return: decrypted message
    """
    logger.info("Decrypting message with key: %s", name)
    start_time = time.time()

    D = NTRUdecrypt(logger)
    D.readPriv(f"{name}.priv")
    D.decryptString(cipher)

    if check_time:
        elapsed = time.time() - start_time
       # logger.info(f"Decryption took {elapsed:.4f} seconds")

    return D.M


def check_key_sparsity(f, threshold=5):
    """
    Check if the secret key f has a sparsity that could make it vulnerable.

    :param f: The polynomial representing the secret key.
    :param threshold: The maximum number of non-zero coefficients allowed.
    :return: True if the key is vulnerable, False otherwise.
    """
    non_zero_coeffs = np.count_nonzero(f)
    return non_zero_coeffs <= threshold


def attack_simulation(N1):
    """
    Simulate an attack on the generated keys based on sparsity.

    :param N1: The NTRUdecrypt object containing the generated keys.
    """
    logger.info("Simulating attack on the generated keys...")

    # Check if the secret key f is vulnerable
    if check_key_sparsity(N1.f, threshold=5):
        logger.warning("The secret key f has too few non-zero coefficients! This key may be vulnerable to attacks.")
        return False
    #else:
    #   logger.debug("The secret key f appears to be sufficiently dense.")

    # Check the public key h as well
    if check_key_sparsity(N1.h, threshold=5):
        logger.warning("The public key h has too few non-zero coefficients! This key may be vulnerable to attacks.")
        return False
    else:
        #logger.debug("The public key h appears to be sufficiently dense.")
        return True
