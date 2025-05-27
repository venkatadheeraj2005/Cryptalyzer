import time
from ecdsa import SigningKey, SECP256k1, NIST521p, NIST192p
from ecdsa import VerifyingKey as vk

def get_curve_by_key_size(key_size: int):
    if key_size == 128:
        return NIST192p
    elif key_size == 256:
        return SECP256k1
    elif key_size == 512:
        return NIST521p
    else:
        raise ValueError("Unsupported key size. Choose from 128, 256, or 512.")

def ecc_operation(key_size: int, message: bytes) -> dict:
    curve = get_curve_by_key_size(key_size)

    t0 = time.time()
    sk = SigningKey.generate(curve=curve)
    vk = sk.get_verifying_key()
    t1 = time.time()

    t2 = time.time()
    signature = sk.sign(message)
    t3 = time.time()

    t4 = time.time()
    valid = vk.verify(signature, message)
    t5 = time.time()

    return {
        "key_size_requested": key_size,
        "curve_used": curve.name,
        "key_generation_time_sec": t1 - t0,
        "signing_time_sec": t3 - t2,
        "verification_time_sec": t5 - t4,
        "signature_valid": valid,
        "signature_hex": signature.hex(),
        "private_key_hex": sk.to_string().hex(),
        "public_key_hex": vk.to_string().hex()
    }


key_size = input("Enter the key size: ")
message = input("Enter the message:")
result = ecc_operation(key_size, message)
for k, v in result.items():
    print(f"{k}: {v}")
