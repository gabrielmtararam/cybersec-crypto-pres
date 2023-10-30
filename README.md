# cybersec-crypto-pres 

Apresentação da aula de Segurança Cibernética 2023/2 - PPGCC - UFSCar

![image](https://github.com/gabrielmtararam/cybersec-crypto-pres/assets/48295298/5754002e-3b51-404c-af5e-c50c5fae510b)

Com a "difusão", temos o espalhamento de cada parte da entrada da cifra relacionando com cada parte da saída, para evitar tentativas de deduzir a chave.

A substituição por si só introduz não linearidade, mas carece de distribuição uniforme em todo o estado, tornando-o suscetível a ataques separados em nível de byte. Para aumentar a segurança, as substituições devem ser alternadas com a codificação para garantir que influenciem todos os bytes. Isso aumenta a complexidade algébrica e fortalece o sistema contra a criptoanálise.<br>
Para imprimir a resposta, usamos a função bytes2matrix, que converte um texto em uma matriz. Ela faz isso separando o texto em pedaços de 4 caracteres e os organiza em diferentes linhas da matriz, além de separar cada caracter em colunas diferentes.

Uma combinação de ShiftRow e MixColunas são utilizadas então para garantir isso, fazendo com que cada byte afete todos os demais em 2 rodadas.

O ShiftRow é uma transformação mais simples, na qual as linhas são deslocadas n-1 colunas para a esquerda, em que n é o número da linha. O objetivo dessa etapa é evitar que as colunas sejam criptografadas de forma independente, pois o AES degeneraria em quatro cifras de bloco independentes.

![image](https://github.com/gabrielmtararam/cybersec-crypto-pres/assets/100847921/1971950d-ff41-4409-b2be-077bc43e23c4)


Já o MixColunas é mais complexo, pois realiza a multiplicação de Matrix no campo de Galois e Rijndael entre as colunas da matriz de estado e uma matriz predefinida, afetando todos os bytes da coluna resultante.

![image](https://github.com/gabrielmtararam/cybersec-crypto-pres/assets/100847921/023cdebd-f0ef-4834-a988-473fbdf4cc93)

Solução de problema:
```
# all the code bellow belongs to cryptoHack as a base code and matrix to be decoded
def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]



# learned from http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def mix_single_column(a):
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)


def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])


def inv_mix_columns(s):
    # see Sec 4.1.3 in The Design of Rijndael
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)


state = [
    [108, 106, 71, 86],
    [96, 62, 38, 72],
    [42, 184, 92, 209],
    [94, 79, 8, 54],
]

# CryptoHack code ends here



# Function made for aes2 issue
def matrix2bytes(matrix_array):
   char_result = []
   for col in matrix_array:
       for line in col:
           char_result.append(chr(line))

   char_result = ''.join(char_result)
   return char_result

# Function made for aes5 issue, we just copy shift columns and modify to shift rows instead of columns
def inv_shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]
    return s

# Calls made to solve aes5 issue
inv_mix_columns(state)
inv_shift_rows(state)
print(matrix2bytes(state))
```
