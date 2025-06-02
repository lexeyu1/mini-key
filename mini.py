import os
import hashlib
import base58
import binascii
from ecdsa import SigningKey, SECP256k1

# --- Константы ---
OUTPUT_FILE = "valid_private_keys.txt"
INPUT_MINI_FILE = "mini.txt"
MIN_KEYS = 100000

def is_valid_minikey(minikey):
    """Проверяет валидность minikey через SHA-256 + '?'."""
    try:
        sha256 = hashlib.sha256()
        sha256.update((minikey + '?').encode('utf-8'))
        digest = sha256.digest()
        return digest[0] == 0x00
    except:
        return False

def minikey_to_private(minikey):
    """Преобразует minikey в приватный ключ (HEX)."""
    return hashlib.sha256(minikey.encode()).hexdigest()

def private_key_to_compressed_address(private_hex):
    """Генерирует сжатый P2PKH Bitcoin-адрес из приватного ключа."""
    sk = SigningKey.from_string(binascii.unhexlify(private_hex), curve=SECP256k1)
    vk = sk.verifying_key
    pub_key = vk.to_string("compressed")

    sha256_pub = hashlib.sha256(pub_key).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_pub)
    hashed = ripemd160.digest()

    network_bitcoin = b'\x00' + hashed  # Mainnet prefix
    checksum = hashlib.sha256(hashlib.sha256(network_bitcoin).digest()).digest()[:4]
    return base58.b58encode(network_bitcoin + checksum).decode()

def private_key_to_uncompressed_address(private_hex):
    """Генерирует несжатый P2PKH Bitcoin-адрес из приватного ключа."""
    sk = SigningKey.from_string(binascii.unhexlify(private_hex), curve=SECP256k1)
    vk = sk.verifying_key
    pub_key = vk.to_string("uncompressed")  # Получаем полный (uncompressed) pubkey

    sha256_pub = hashlib.sha256(pub_key).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_pub)
    hashed = ripemd160.digest()

    network_bitcoin = b'\x00' + hashed  # Mainnet prefix
    checksum = hashlib.sha256(hashlib.sha256(network_bitcoin).digest()).digest()[:4]
    return base58.b58encode(network_bitcoin + checksum).decode()

def generate_minikeys(count):
    """Генерирует указанное количество minikey и сохраняет приватные ключи в файл."""
    count = max(count, MIN_KEYS)
    print(f"[+] Начинаем генерацию {count} мини-ключей...")
    generated = 0
    with open(OUTPUT_FILE, 'w') as f:
        while generated < count:
            entropy = os.urandom(20)
            candidate = 'S' + base58.b58encode(entropy).decode('utf-8')[:21]
            if len(candidate) != 22:
                continue
            if is_valid_minikey(candidate):
                private_hex = minikey_to_private(candidate)
                f.write(f"{private_hex}\n")
                generated += 1
                if generated % 1000 == 0:
                    print(f"Сохранено {generated} ключей...")

    print(f"\n[✓] Генерация завершена! Всего сохранено: {generated}")
    print(f"Файл: {OUTPUT_FILE}")

def verify_single_minikey():
    """Проверяет minikey, запрашивая повторный ввод при неверной длине или невалидности."""
    while True:
        mk = input("Введите minikey (22 или 30 символов) или 'q' для выхода: ").strip()
        if mk.lower() == 'q':
            print("[-] Операция отменена.")
            return

        if len(mk) not in (22, 30):
            print("[!] Неверная длина minikey. Должно быть 22 или 30 символов.")
            continue

        if not is_valid_minikey(mk):
            print("[-] Введён невалидный minikey. Попробуйте снова.")
            continue

        # Если всё верно — выходим из цикла
        break

    private_hex = minikey_to_private(mk)
    addr_compressed = private_key_to_compressed_address(private_hex)
    addr_uncompressed = private_key_to_uncompressed_address(private_hex)

    print("\n[+] Результат проверки:")
    print(f"Minikey:                  {mk}")
    print(f"Private Key (HEX):        {private_hex}")
    print(f"BTC Address (compressed): {addr_compressed}")
    print(f"BTC Address (uncompressed): {addr_uncompressed}\n")

def verify_file_minikeys():
    """Проверяет все minikey из файла mini.txt."""
    try:
        with open(INPUT_MINI_FILE, 'r') as f:
            minikeys = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        print(f"[-] Файл '{INPUT_MINI_FILE}' не найден.")
        return

    print(f"[+] Проверяются minikey из файла '{INPUT_MINI_FILE}'...\n")
    for mk in minikeys:
        if len(mk) not in (22, 30):
            print(f"[!] Пропущен (неправильная длина): {mk}")
            continue
        if is_valid_minikey(mk):
            private_hex = minikey_to_private(mk)
            addr_compressed = private_key_to_compressed_address(private_hex)
            addr_uncompressed = private_key_to_uncompressed_address(private_hex)
            print(f"Minikey:                  {mk}")
            print(f"Private Key (HEX):        {private_hex}")
            print(f"BTC Address (compressed): {addr_compressed}")
            print(f"BTC Address (uncompressed): {addr_uncompressed}\n")
        else:
            print(f"[-] Невалидный: {mk}\n")

def main_menu():
    print("\n=== Bitcoin Mini Private Key Tool ===")
    print("1. Генерация mini private key (запись в файл)")
    print("2. Проверка minikey (вручную или из файла mini.txt)")
    choice = input("Выберите режим (1 или 2): ")

    if choice == "1":
        try:
            num_keys = int(input(f"Введите количество ключей (не меньше {MIN_KEYS}): "))
        except ValueError:
            num_keys = MIN_KEYS
        generate_minikeys(num_keys)
    elif choice == "2":
        print("\n1. Проверить один minikey")
        print("2. Проверить minikey из файла mini.txt")
        sub_choice = input("Выберите подрежим (1 или 2): ")
        if sub_choice == "1":
            verify_single_minikey()
        elif sub_choice == "2":
            verify_file_minikeys()
        else:
            print("[-] Неверный выбор.")
    else:
        print("[-] Неверный режим.")

if __name__ == "__main__":
    main_menu()