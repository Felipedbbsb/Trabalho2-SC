import random
import oaep
import hashlib

KEY_BITS_SIZE = 1024
PADDING_SIZE = KEY_BITS_SIZE%-41

def gcd(a, b):
   while a != 0:
      a, b = b % a, a
   return b

def find_mod_inverse(a, m):
    if gcd(a, m) != 1:
        return None
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
   
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m

def rabin_miller(num):
   s = num - 1
   t = 0
   
   while s % 2 == 0:
      s = s // 2
      t += 1
   for trials in range(5):
      a = random.randrange(2, num - 1)
      v = pow(a, s, num)
      if v != 1:
         i = 0
         while v != (num - 1):
            if i == t - 1:
               return False
            else:
               i = i + 1
               v = (v ** 2) % num
      return True
def is_prime(num):
    if (num < 2):
        return False
    low_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 
   67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 
   157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 
   251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313,317, 331, 337, 347, 349, 
   353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 
   457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 
   571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 
   673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 
   797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 
   911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]
	
    if num in low_primes:
        return True
    for prime in low_primes:
        if (num % prime == 0):
            return False
    return rabin_miller(num)

def generate_large_prime(keysize = 1024):
    while True:
        num = random.randrange(2**(keysize-1), 2**(keysize))
        if is_prime(num):
            return num

def generateKey(key_size):
    # Gera q e p como dois primos grandes a partir do teste de primalidade de Miller-Rabin
    p = generate_large_prime(key_size)
    q = generate_large_prime(key_size)
    n = p * q
        
    # Criar um número relativamente primo a (p-1)*(q-1).
    while True:
        e = random.randrange(2 ** (key_size - 1), 2 ** (key_size))
        if gcd(e, (p - 1) * (q - 1)) == 1:
            break
    
    d = find_mod_inverse(e, (p - 1) * (q - 1))
    public_key = (n, e)
    private_key = (n, d)
    return (public_key, private_key)

def cifrar(letras, public_key):
    n,e = public_key[0], public_key[1]
    tam = len(letras)
    i = 0
    texto = []
    while(i < tam):
        k = letras[i]
        d = pow(k,e,n)
        texto.append(d)
        i += 1
    return texto

def descifrar(cifra, private_key):
    n, d = private_key[0], private_key[1]
    lista = []
    i = 0
    tamanho = len(cifra)
    # texto=cifra ^ d mod n
    while i < tamanho:
        letra = pow(cifra[i],d,n)
        letra = letra.to_bytes()
        lista.append(letra)
        i += 1
    return lista

def assinar(texto: str, public_key):
    sha3_text = hashlib.sha3_256(texto.encode())
    text_hash = sha3_text.hexdigest()
    print("Message hash:", text_hash)
    hash_cifrado = oaep.oaep_encode(bytes(text_hash.encode()),PADDING_SIZE)
    return hash_cifrado

if __name__ == "__main__":
    plain_text = input("Insira sua mensagem: ")
    text = oaep.oaep_encode(bytes(plain_text.encode()),PADDING_SIZE)
    print("Padding adicionado:",text)
    # public_key é composto por (n, e)
    # n = p*q
    public_key, private_key = generateKey(1024)
    
    print('Public key:', public_key)
    print('Private key:', private_key)
    texto_cifrado = cifrar(text,public_key)
    # print('Mensagem cifrada:', text_cipher)
    original_text = descifrar(texto_cifrado,private_key)
    original_text = b''.join(original_text)
    print("Decifrando:",original_text)
    original_text = oaep.oaep_decode(bytes(original_text), PADDING_SIZE)
    original_text = ''.join([chr(x) for x in original_text])
    print('Mensagem original:', original_text)
    print("Assinatura:",assinar(plain_text, public_key))