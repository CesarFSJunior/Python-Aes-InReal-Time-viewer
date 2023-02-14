from KeyExpansion import keyExpansion
from matrizes import Sbox, Mix, InvSbox, MixReverse
import os

clear = lambda: os.system('cls')
clear()

def show(seeProcess, i = " "):
    if seeProcess:
        print(i)

def skip(seeProcess):
    if seeProcess:        
        input('Enter para continuar')
        clear()

def AddRoundKey(seeProcess, matriz, w, Round = -1):
    roundKey = [[],[],[],[]]
    if Round >= 0:
        roundMult = 4 * (Round + 1)
    else:
        roundMult = 0
    for i in range(4):
        for l in range(4):
            s = w[ i + roundMult ]
            roundKey[ l ].append( s[l] )

    for i in range(4):
        NewLine = []
        for l in range(4):
            Key = hex( int( matriz[i][l], 16 ) ^ int( roundKey[i][l], 16 ) ).split('x')[1]
            NewLine.append(Key)
            if len(NewLine[l]) == 1:
                NewLine[l] ="0" + NewLine[l]
        matriz[i] = NewLine

    show(seeProcess, "Add round Key")
    show(seeProcess)
    for i in roundKey:
        show(seeProcess, i)
    show(seeProcess)
    for i in matriz:
        show(seeProcess, i)
    skip(seeProcess)
    return matriz

def subBytes(seeProcess, matriz, Sbox):
    for i in range(4):
        newLine = []
        for l in range(4):
            item = Sbox[int(matriz[i][l][0], 16)][int(matriz[i][l][1], 16)]
            newLine.append(item)
        matriz[i] = newLine

    show(seeProcess, "SubBytes")
    show(seeProcess)
    for i in matriz:
        show(seeProcess, i)
    skip(seeProcess)
    return matriz

def ShifRows(seeProcess, matriz, direction):
    if direction == "normal":
        for i in range(4):
            for l in range(i):
                lastDigit = matriz[i][0]
                matriz[i] = matriz[i][1:]
                matriz[i].append(lastDigit)
    else:
        for i in range(4):
            temp = matriz[i]
            for l in range(i):
                lastDigit = temp[3]
                temp = temp[:3]
                temp.insert(0, lastDigit)
            matriz[i] = temp
    
    show(seeProcess, "ShifRows")
    show(seeProcess)
    for i in matriz:
        show(seeProcess, i)
    skip(seeProcess)
    return matriz

def MixColumns(seeProcess, matriz, Mix = Mix):
    for i in range(4):
        NewColumn = []
        for j in range(4):
            FieldProduct = 0
            for k in range(4): 
                value1 = matriz[k][i]
                value2 = Mix[j][k]
                GFMultResult = GfMul(value1, value2)
                FieldProduct ^= GFMultResult

            NewColumn.append(FieldProduct)

        for j in range(len(NewColumn)):
            value = hex(NewColumn[j]).split('x')[1]
            if len(value) == 1:
                matriz[j][i] = '0' + value
            else:
                matriz[j][i] = hex(NewColumn[j]).split('x')[1]

    return matriz

def GfMul( value1, value2):
    value1 = int(value1, 16)
    value2 = int(value2, 16)
    multiplicationProduct = 0
    irreduciblePolynomial = 0x11b

    while not value1 == 0 and not value2 == 0:
        if value2 & 1:
            multiplicationProduct ^= value1

        if value1 & 0x80:
            value1 = (value1 << 1) ^ irreduciblePolynomial
        else:
            value1 <<= 1
        value2 >>= 1
    return multiplicationProduct

def XorInitVector(seeProcess, matriz, iv):
    for i in range(4):
        newLine = []
        for l in range(4):
            xor = hex(int(matriz[i][l], 16) ^ int(iv[i][l], 16)).split('x')[1]
            newLine.append(xor)
            if len(newLine[l]) == 1:
                newLine[l] = "0" + newLine[l]
        matriz[i] = newLine

    show(seeProcess,'cbc')
    show(seeProcess)
    for i in matriz:
        show(seeProcess, i)
    skip(seeProcess)
    return matriz

def aesDefaultEncrypt(seeProcess, matriz, Round, w, Nr, Sbox = Sbox, Mix = Mix, direction = "normal"):
    if direction == "normal":
        if Round < Nr - 1:
            matriz = AddRoundKey(seeProcess, MixColumns(seeProcess, ShifRows(seeProcess, subBytes(seeProcess, matriz, Sbox), direction), Mix), w, Round)
        else:
            matriz = AddRoundKey(seeProcess, ShifRows(seeProcess, subBytes(seeProcess, matriz, Sbox), direction), w, Round)
    else:
        if Round > -1:
            matriz = MixColumns(seeProcess, AddRoundKey(seeProcess, subBytes(seeProcess, ShifRows(seeProcess, matriz, direction), Sbox), w, Round), Mix)
        else:
            matriz = AddRoundKey(seeProcess, subBytes(seeProcess, ShifRows(seeProcess, matriz, direction), Sbox), w, Round)
    return matriz

def Encrypt(plaintext, key, method, seeProcess = False, initVector = "00000000000000000000000000000000"):

    if len(key) > 32:
        return "Erro: Key maior que 32 caracteres"

    if len(key) > 16:
        if len(key) - 16 > 8:
            Nr = 14
        else:
            Nr = 12
    else:
        Nr = 10

    w = keyExpansion(key, Nr)
    
    for i in range(len(w)):
        if i % 4 == 0:
            show(seeProcess)
        show(seeProcess, "{w:0>2}: {i}".format(w=i, i=w[i]))
    skip(seeProcess)

    Output = ""
    newIv = []

    if len(plaintext) % 16 > 0:
        add = 1
    else:
        add = 0

    if method == "cfb" or method == "ofb":
        blockRange = len(plaintext)
    else:
        blockRange = (len(plaintext) // 16)+add

    for BlocksRound in range(blockRange):
        if method == "ctr":
            counter = hex(int(initVector, 16) + BlocksRound).split('x')[1]
            iv = [[],[],[],[]]
            for i in range(16):
                iv[i%4].append(counter[ i*2 : ( i*2 ) + 2 ])
        else:
            if BlocksRound == 0:
                iv = [[],[],[],[]]
                oldIv = [[],[],[],[]]
                for i in range(16):
                    iv[i%4].append(initVector[ i*2 : ( i*2 ) + 2 ])
                    oldIv[i%4].append(initVector[ i*2 : ( i*2 ) + 2 ])
            else:
                iv = newIv

        matriz = [[],[],[],[]]
        plaintextBlockCounter = BlocksRound * 16
        for i in range(16):
            if len(plaintext) > i + plaintextBlockCounter:
                matriz[i%4].append(format(ord(plaintext[i + plaintextBlockCounter]), 'x'))
            else:
                matriz[i%4].append('00')

        # matriz = [[],[],[],[]]
        # plaintextBlockCounter = BlocksRound * 16
        # for i in range(16):
        #     if len(plaintext) > i + plaintextBlockCounter:
        #         matriz[i%4].append((plaintext[(i + plaintextBlockCounter) * 2 : ((i + plaintextBlockCounter) * 2) + 2]))
        
        # matriz = [['01','89','fe','76'],
        #           ['23','ab','dc','54'],
        #           ['45','cd','ba','32'],
        #           ['67','ef','98','10']]

        # matriz = [['00', '04', '08', '0c'],
        #           ['01', '05', '09', '0d'],
        #           ['02', '06', '0a', '0e'],
        #           ['03', '07', '0b', '0f']]

        # matriz = [['6b','2e','e9','73'],
        #           ['c1','40','3d','93'],
        #           ['be','9f','7e','17'],
        #           ['e2','96','11','2a']]

        if not method == "cfb" or not method == "ofb" or not method == "ctr":
            show(seeProcess, 'matriz')
            for i in matriz:
                show(seeProcess, i)
            skip(seeProcess)
        else:
            show(seeProcess, 'iv')
            for i in iv:
                show(seeProcess, i)
            skip(seeProcess)

        if method == "cbc":
            XorInitVector(seeProcess, matriz, iv)

        if method == "cfb" or method == "ofb" or method == "ctr":
            iv = AddRoundKey(seeProcess, iv, w)
        else:
            matriz = AddRoundKey(seeProcess, matriz, w)

        for Round in range(Nr):
            if method == "cfb" or method == "ofb" or method == "ctr":
                iv = aesDefaultEncrypt(seeProcess, iv, Round, w, Nr)
            else:
                matriz = aesDefaultEncrypt(seeProcess, matriz, Round, w, Nr)

        if method == "cbc":
            newIv = matriz

        elif method == "cfb" or method == "ofb":

            oldIvString = ""
            for i in range(4):
                for l in range(4):
                    oldIvString = oldIvString + oldIv[l][i]

            oldIvStringNewLastDigit = hex(int(iv[0][0], 16) ^ ord(plaintext[BlocksRound])).split('x')[1]
            
            if method == "cfb":
                if len(oldIvStringNewLastDigit) == 1:
                    oldIvString = oldIvString[2:] + "0" + oldIvStringNewLastDigit
                else:
                    oldIvString = oldIvString[2:] + oldIvStringNewLastDigit
            else:
                oldIvString = oldIvString[2:] + iv[0][0]

            for i in range(4):
                 for l in range(4):
                    iv[l][i] = oldIvString[((i * 4) + l) * 2 : (((i * 4) + l) * 2) + 2]
                    oldIv[l][i] = oldIvString[((i * 4) + l) * 2 : (((i * 4) + l) * 2) + 2]
            newIv = iv

        if method == 'cfb' or method == "ofb":
            if len(oldIvStringNewLastDigit) == 1:
                Output = Output + '0' + oldIvStringNewLastDigit
            else:
                Output = Output + oldIvStringNewLastDigit
        elif method == "ctr":
            for i in range(4):
                for l in range(4):
                    ctrXor = hex(int(matriz[l][i], 16) ^ int(iv[l][i], 16)).split('x')[1]
                    if len(ctrXor) == 1:
                        Output = Output + "0" + ctrXor
                    else:
                        Output = Output + ctrXor
        else:
            for i in range(4):
                for l in range(4):
                    Output = Output + matriz[l][i]

    return Output

def Decrypt(cyphertext, key, method, seeProcess = False, initVector = "00000000000000000000000000000000"):
    
    if len(key) > 32:
        return "Erro: Key maior que 32 caracteres"

    if len(key) > 16:
        if len(key) - 16 > 8:
            Nr = 14
        else:
            Nr = 12
    else:
        Nr = 10

    w = keyExpansion(key, Nr)
    
    for i in range(len(w)):
        if i % 4 == 0:
            show(seeProcess)
        show(seeProcess, "{w:0>2}: {i}".format(w=i, i=w[i]))
    skip(seeProcess)

    Output = ""
    newIv = []

    if len(cyphertext) % 16 > 0:
        add = 1
    else:
        add = 0

    if method == "cfb" or method == "ofb":
        blockRange = len(cyphertext) // 2
    else:
        blockRange = (len(cyphertext) // 32)+add

    for BlocksRound in range(blockRange):
        if method == "ctr":
            Counter = hex(int(initVector, 16) + BlocksRound).split('x')[1]
            iv = [[],[],[],[]]
            for i in range(16):
                iv[i%4].append(Counter[ i*2 : ( i*2 ) + 2 ])
        else:
            if BlocksRound == 0:
                iv = [[],[],[],[]]
                oldIv = [[],[],[],[]]
                for i in range(16):
                    iv[i%4].append(initVector[ i*2 : ( i*2 ) + 2 ])
                    oldIv[i%4].append(initVector[ i*2 : ( i*2 ) + 2 ])
            else:
                iv = newIv

        matriz = [[],[],[],[]]
        plaintextBlockCounter = BlocksRound * 32
        for i in range(16):
            matriz[i%4].append(cyphertext[(i * 2) + plaintextBlockCounter: ((i * 2)+2 ) + plaintextBlockCounter])

        if method == "cbc":
            newIv = []
            for i in matriz:
                newIv.append(i)

        # matriz = [['01','89','fe','76'],
        #           ['23','ab','dc','54'],
        #           ['45','cd','ba','32'],
        #           ['67','ef','98','10']]

        # matriz = [['00', '04', '08', '0c'],
        #           ['01', '05', '09', '0d'],
        #           ['02', '06', '0a', '0e'],
        #           ['03', '07', '0b', '0f']]

        # matriz = [['6b','2e','e9','73'],
        #           ['c1','40','3d','93'],
        #           ['be','9f','7e','17'],
        #           ['e2','96','11','2a']]

        if not method == "cfb" or not method == "ofb" or method == "ctr":
            show(seeProcess, "Input text")
            show(seeProcess)
            for i in matriz:
                show(seeProcess, i)
            skip(seeProcess)
        else:
            show(seeProcess, "Input text iv")
            show(seeProcess)
            for i in iv:
                show(seeProcess, i)
            skip(seeProcess)

        if method == "cfb" or method == "ofb" or method == "ctr":
            iv = AddRoundKey(seeProcess, iv, w)
        else:
            matriz = AddRoundKey(seeProcess, matriz, w, Nr - 1)

        if method == "cfb" or method == "ofb" or method == "ctr":
            for Round in range(Nr):
                iv = aesDefaultEncrypt(seeProcess, iv, Round, w, Nr)
        else:
            for Round in range(Nr - 2 , -2, -1):
                matriz = aesDefaultEncrypt(seeProcess, matriz, Round, w, Nr, InvSbox, MixReverse, "Inverse")

        if method == "cbc":
            XorInitVector(seeProcess, matriz, iv)

        elif method == "cfb" or method == "ofb":

            oldIvString = ""
            for i in range(4):
                for l in range(4):
                    oldIvString = oldIvString + oldIv[l][i]

            oldIvStringNewLastDigit = hex(int(iv[0][0], 16) ^ int(cyphertext[BlocksRound * 2: (BlocksRound * 2) + 2], 16)).split('x')[1]

            if method == "cfb":
                oldIvString = oldIvString[2:] + cyphertext[BlocksRound * 2: (BlocksRound * 2) + 2]
            else:
                oldIvString = oldIvString[2:] + iv[0][0]

            for i in range(4):
                 for l in range(4):
                    iv[l][i] = oldIvString[((i * 4) + l) * 2 : (((i * 4) + l) * 2) + 2]
                    oldIv[l][i] = oldIvString[((i * 4) + l) * 2 : (((i * 4) + l) * 2) + 2]
            newIv = iv

        if method == 'cfb' or method == "ofb":
            if len(oldIvStringNewLastDigit) == 1:
                Output = Output + '0' + oldIvStringNewLastDigit
            else:
                Output = Output + oldIvStringNewLastDigit
        elif method == "ctr":
            for i in range(4):
                for l in range(4):
                    ctrxor = hex(int(iv[l][i], 16) ^ int(matriz[l][i], 16)).split('x')[1]
                    if len(ctrxor) == 1:
                        Output = Output + "0" + ctrxor
                    else:
                        Output = Output + ctrxor
        else:
            for i in range(4):
                for l in range(4):
                    Output = Output + matriz[l][i]

    OutputToString = ""
    for i in range(len(Output)//2):
        OutputToString = OutputToString + chr(int(Output[i*2 : (i*2) + 2], 16))
    
    Output = OutputToString
    return Output
