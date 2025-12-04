import random

# ————————————————————————————————————————
# Funzioni di test crittografico
# ————————————————————————————————————————

def hamming_weight(x):
    return bin(x).count("1")

def hamming_distance(x, y):
    return bin(x ^ y).count("1")

def rotate_left(x, k, bits=64):
    return ((x << k) | (x >> (bits - k))) & ((1 << bits) - 1)

def has_long_run(x, max_run=5):
    run = 1
    prev = x & 1
    x >>= 1
    while x:
        curr = x & 1
        run = run + 1 if curr == prev else 1
        if run > max_run:
            return True
        prev = curr
        x >>= 1
    return False


def crypto_test(full, high, low):
    """Controlli crittografici su un u128 spezzato in high/low"""
    reasons = []

    # 1. Hamming weight totale ~70%
    hw_total = hamming_weight(full)
    if hw_total < 80:  # 70% di 128 ≈ 90
        reasons.append(f"Hamming weight totale troppo bassa: {hw_total}")

    # 2. Run limit su high e low
    if has_long_run(high):
        reasons.append("High ha sequenze troppo lunghe di bit consecutivi")
    if has_long_run(low):
        reasons.append("Low ha sequenze troppo lunghe di bit consecutivi")

    # 3. Mixing crittografico globale
    mixed = rotate_left(full, 64) ^ full
    hw_mixed = hamming_weight(mixed)
    if not (40 <= hw_mixed <= 60):
        reasons.append(f"Hamming weight del mixing globale fuori range: {hw_mixed}")


    return len(reasons) == 0, reasons


# ————————————————————————————————————————
# Generazione 64-bit bitwise con bias adattivo
# ————————————————————————————————————————

def generate_64bit_bitwise_adaptive(rng, target_ratio=0.7):
    val = 0
    run = 0
    prev_bit = None
    ones_count = 0
    for i in range(64):
        remaining_bits = 64 - i
        # calcola la probabilità adattiva di 1
        expected_ones = target_ratio * 64
        bias = max(min((expected_ones - ones_count) / remaining_bits, 1), 0)
        if prev_bit is not None and run >= 4:
            bit = 1 - prev_bit  # limita i run
        else:
            bit = 1 if rng.random() < bias else 0
        val |= bit << i

        # aggiorna run e conteggio
        if prev_bit is not None and bit == prev_bit:
            run += 1
        else:
            run = 1
        prev_bit = bit
        ones_count += bit
    return val

# ————————————————————————————————————————
# Generazione 128-bit con adattamento Hamming weight
# ————————————————————————————————————————

def generate_128bit_adaptive(seed=None, target_ratio=0.7):
    rng = random.Random(seed)
    while True:
        high = generate_64bit_bitwise_adaptive(rng, target_ratio)
        low  = generate_64bit_bitwise_adaptive(rng, target_ratio)
        # Mix crittografico finale
        full = (high << 64) | low
        return full, high, low

# ————————————————————————————————————————
# Genera N costanti
# ————————————————————————————————————————

def generate_n_constants(n, seed=None):
    constants = []
    for i in range(n):
        full, high, low = generate_128bit_adaptive(seed)
        constants.append((full, high, low))
        if seed is not None:
            seed += 1  # cambia seed per la prossima costante
    return constants

# ————————————————————————————————————————
# Main
# ————————————————————————————————————————

if __name__ == "__main__":
    N = 10
    constants = generate_n_constants(N, seed=12345)

    for i, (full, high, low) in enumerate(constants):
        test_result, reason =  crypto_test(full, high, low)
        print(f"Costante #{i+1}:")
        print(f"Full : 0x{full:032X} | {full:0128b}")
        print(f"High : 0x{high:016X} | {high:064b}")
        print(f"Low  : 0x{low:016X} | {low:064b}")
        print(f"MASK_TO_BLOCK_SIZE(0x{high:016X}, 0x{low:016X})")
        print("Test crittografico:", "SI" if test_result else "NO")
        if not test_result:
            print("Motivo:", reason)
        print("-"*60)
