import numpy as np
import random

sbox = [[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
              [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
              [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
              [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
              [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
              [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
              [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
              [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
              [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
              [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
              [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
              [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
              [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
              [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
              [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
              [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]]

Galois_matrix = np.array([[2, 3, 1, 1],
                         [1, 2, 3, 1],
                         [1, 1, 2, 3],
                         [3, 1, 1, 2]], dtype=np.int8)

rcon = [[chr(1), chr(0), chr(0), chr(0)], [chr(2), chr(0), chr(0), chr(0)],
             [chr(4), chr(0), chr(0), chr(0)], [chr(8), chr(0), chr(0), chr(0)],
             [chr(16), chr(0), chr(0), chr(0)], [chr(32), chr(0), chr(0), chr(0)],
             [chr(64), chr(0), chr(0), chr(0)], [chr(128), chr(0), chr(0), chr(0)],
             [chr(27), chr(0), chr(0), chr(0)], [chr(54), chr(0), chr(0), chr(0)]]

nonce = random.getrandbits(128)




#-----------------------------------------------------------------------------------------------------------------------------

# Funcoes auxiliarde conversao

def bytes_to_hex_string(byte_array):
    hex_string = ''.join('{:02x}'.format(byte) for byte in byte_array)
    return hex_string

def bytes_to_hex(byte_string):
    hex_string = ''.join('{:02x}'.format(byte) for byte in byte_string)
    return hex_string

# Função auxiliar para converter uma matriz numpy para um objeto bytes
def numpy_to_bytes(numpy_array):
    return bytes(numpy_array.tolist())

def list2HexString(list):
    string = ""
    for i in range(0, len(list)):
        string = string + str(hex(list[i]))[2:]
    return string

def str2Hex(string):
    hex_values = [ord(chr) for chr in string]
    return list2HexString(hex_values)


def int2String(number):
    string = ''
    while (number != 0):
        string += chr(number % 256)
        number = int(number / 256)
    string = string[::-1]
    return string


def string2List(string):
    list = []
    for i in range(0, 16):
        list.append(string[i])
    return list

def list2String(list):
    string = ""
    for i in range(0, len(list)):
        string = string + list[i]
    return string

def listRotate(lst, amount):
    if lst:
        lst = lst[amount:] + lst[:amount]
    return lst



#-----------------------------------------------------------------------------------------------------------------------------
#Geradores de chaves e manipulacao

def generate_key():
    # Gera uma chave aleatória de 128 bits (16 bytes)
    key = np.random.randint(256, size=16, dtype=np.uint8)
    return key

#   Gera uma lista que contem todas as chaves utilizadas na cifra de bloco AES.
def generateRoundKeys(key):
    round_keys = []
    round_keys.append(key)
    list_temp = []
    for i in range(10):
        for j in range(4):
            if j == 0:  # CASO INICIAL

                temp = round_keys[i][12:16]  # amostra 4 ultimas letras
                temp.append(temp.pop(0))  # rotaciona coluna
                temp = sub_bytes(temp)  # traduz pela tabela subBytes
                aux = listXOR(rcon[i], round_keys[i][0:4])  #

                list_temp = listXOR(temp, aux)  # XOR com coluna da tabela RCON e com 4 primeiras letras da ultima chave
            else:  # CASO INTERMEDIARIO
                temp = list_temp[j * 4 - 4: j * 4]  # amostra 4 ultimas letras geradas
                aux = round_keys[i][j * 4: j * 4 + 4]  #
                temp = listXOR(temp, aux)  # XOR com letras de 4 colunas à esquerda
                for k in range(4):
                    list_temp.append(temp[k])
        round_keys.append(list_temp)  # armazenando chave de rodada
    return round_keys

#-----------------------------------------------------------------------------------------------------------------------------
#|Transformadores do bloco de encriptacao
def sub_bytes(state):
    result = []
    for byte in state:
        byte = ord(byte)
        msb = ((byte & 0xF0) >> 4 ) # Extrai os 4 bits mais significativos
        lsb = (byte & 0x0F ) # Extrai os 4 bits menos significativos
        substituted_byte = chr(sbox[msb][lsb])  # Obtém o byte substituído da tabela
        result.append(substituted_byte)
    return (result)




def shift_rows(state):
    new_row2 = listRotate(state[1:5], 1)
    new_row3 = listRotate(state[2:6], 2)
    new_row4 = listRotate(state[3:7], 3)
    new_state = []
    for i in range(4):
        new_state.extend([state[4 * i], new_row2[i], new_row3[i], new_row4[i]])
    return new_state

def mix_columns(state):
    # Combinação das colunas do estado usando multiplicação matricial
    ints = [int(ord(x)) for x in state]
    new_ints = []
    for i in range(4):
        new_ints += np.matmul(Galois_matrix, np.array(ints[i: i + 4], dtype=np.uint8)).tolist()
    return [chr(x) for x in new_ints]

def listXOR(str1, str2):
    str_final = []
    for i in range(len(str1)):
        str_final.append(chr(ord(str(str1[i])) ^ ord(str(str2[i]))))  # bitwise XOR em cada caracter
    return str_final

def add_round_key(state, round_key):
    temp = []
    for i in range(len(state)):
        temp.append(chr(ord(state[i]) ^ ord(round_key[i])))
    return state

#-----------------------------------------------------------------------------------------------------------------------------


def encrypt_block(plaintext, key):
    plaintext = string2List(plaintext)
    key = string2List(key)
    round_keys = generateRoundKeys(key)
    state = add_round_key(plaintext, round_keys[0])

    # Aplica as operações da cifra para cada rodada
    for round_key in round_keys:
        state = sub_bytes(state)
        state = shift_rows(state)

        state = mix_columns(state)
        state = add_round_key(state, round_key)

    # Última rodada sem mix_columns
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[-1])

    ciphertext = state[:len(plaintext)]
    return ciphertext


def Counter_Mode(message, key):

    final_message = ''
    block_size = 16  # AES block size is 128 bits (16 bytes)
    ciphertext = b""
    num_blocks = int(len(message) /block_size)
    # Para cada 16 caracteres da mensagem (16 char * 8 bits = 128 bits)
    for i in range(0, num_blocks):  #
        count = i  #

        str_nonce = int2String(nonce + count)  # Computa nonce + count
        plaintext_padding = message[i * 16: i * 16 + 16]  # Separa bloco de 128 bits da mensagem
        cipher_block = encrypt_block(str_nonce, key)  # Realiza cifra de bloco com nonce e chave fornecida

        final_message += list2String(listXOR(cipher_block, plaintext_padding))  # Armazena resultado do XOR do bloco cifrado com o segmento da mensagem

    remainder = len(message) % 16
    if remainder != 0:  # Caso haja segmento final com comprimento < 16 caracteres:
        plaintext_block = message[len(message) - remainder:]  # Separa segmento restante da mensagem
        count += 1  #
        str_nonce = int2String(nonce + count)  # Computa nonce + count
        cipher_block = encrypt_block(str_nonce, key)  # Realiza cifra de bloco com nonce e chave fornecida
        for i in range(16 - remainder):  # Realiza padding no segmento da mensagem
            plaintext_block += '0'
        final_message += list2String(listXOR(cipher_block, plaintext_block)[
                                     :remainder])  # Armazena resultado do XOR do bloco cifrado com o segmento da mensagem

    return final_message

# Exemplo de uso:

def main():
    #Geração de chave
    key = list2HexString(generate_key()) # geração de chaves já convertida em string
    print("\n-----------------------------------------------------------------------------------------------------------------------------")
    print("Key:\t\t",key)
    print("-----------------------------------------------------------------------------------------------------------------------------")

    #key = np.array([ 15 , 92 ,190 , 23 ,252 ,191 ,128 ,148 ,214 , 93 ,107 ,228, 178, 141 ,141  ,74], dtype=np.uint8)

    plaintext = "Hello, World! uma mensagem grande e com #$%¨&*()g"
    print("\n-----------------------------------------------------------------------------------------------------------------------------")
    print("MENSAGEM:\t\t", plaintext)
    print("-----------------------------------------------------------------------------------------------------------------------------")
    ciphertext = Counter_Mode(plaintext, key)

    print("\n-----------------------------------------------------------------------------------------------------------------------------")
    print("MENSAGEM:\t\t", str2Hex(ciphertext))
    print("-----------------------------------------------------------------------------------------------------------------------------")

    decrypted_data = Counter_Mode(ciphertext, key)
    print("\n-----------------------------------------------------------------------------------------------------------------------------")
    print("MENSAGEM:\t\t", decrypted_data)
    print("-----------------------------------------------------------------------------------------------------------------------------")

if __name__ == "__main__":
    main()


