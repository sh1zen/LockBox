import random

N = 64

def check_fixed_points(pi):
    return sum(1 for i, v in enumerate(pi) if i == v)

def cycle_lengths(pi):
    visited = [False]*N
    cycles = []
    for i in range(N):
        if visited[i]:
            continue
        length = 0
        j = i
        while not visited[j]:
            visited[j] = True
            j = pi[j]
            length += 1
        cycles.append(length)
    return cycles

def row_connectivity(pi, row_size=8):
    rows_hit = [0]*row_size
    for i, v in enumerate(pi):
        rows_hit[i//row_size] += 1
    return sum(1 for x in rows_hit if x>0)/row_size

def col_connectivity(pi, col_size=8):
    cols_hit = [0]*col_size
    for i, v in enumerate(pi):
        cols_hit[i % col_size] += 1
    return sum(1 for x in cols_hit if x>0)/col_size

def generate_pi_box(max_attempts=50000):
    best_pi = None
    best_score = -1
    for _ in range(max_attempts):
        pi = list(range(N))
        random.shuffle(pi)

        # penalizza fixed points
        fp = check_fixed_points(pi)
        if fp > 0:
            continue

        # ciclo unico?
        cycles = cycle_lengths(pi)
        if len(cycles) != 1:
            continue

        # calcola score semplice combinato
        row_conn = row_connectivity(pi)
        col_conn = col_connectivity(pi)
        score = row_conn + col_conn

        if score > best_score:
            best_score = score
            best_pi = pi
            if best_score >= 1.95:  # row + col >= 75%
                break
    return best_pi

if __name__ == "__main__":
    pi_box = generate_pi_box()
    if pi_box is None:
        print("Non è stato trovato un PI_BOX ottimale")
    else:
        print("PI_BOX ottimale trovata:")
        print(pi_box)
