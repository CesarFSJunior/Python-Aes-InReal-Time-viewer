from matrizes import Sbox, Rc

def keyExpansion(Outkey, Nr):

    if len(Outkey) > 32:
        return False

    def keyToHex(plaintext):
        output = ""
        for i in plaintext:
            output += hex(ord(i)).split('x')[1]
        return output
    
    key = keyToHex(Outkey)
    # key = Outkey

    def RotWord(i):
        lastDigitTemp = i[0]
        i = i[1:]
        i.append(lastDigitTemp)
        return i

    def SubWord(i):
        for l in range(4):
            item = i[l]
            line = int(item[0], 16)
            column = int(item[1], 16)
            SboxLine = Sbox[line]
            i[l] = SboxLine[column]
        return i

    def RCon(i, Nk, Counter):
        i[0] = hex(int(i[0], 16)^int(Rc[int(Counter/Nk)],16)).split('x')[1]
        return i

    w = [[],[],[],[]]

    if len(key) > 32:
        if len(key) - 32 > 16:
            l = 2
        else:
            l = 1
        for i in range(l * 2):
            w.append([])

    for i in range(len(w)):
        for l in range(4):
            w[i].append(key[((i * 4) + l) * 2 : (((i * 4) + l) * 2) + 2])

    # Nr = 14
    
    # w = [['2b','7e','15','16'],
    #      ['28','ae','d2','a6'],
    #      ['ab','f7','15','88'],
    #      ['09','cf','4f','3c']]

    # w = [['0f','15','71','c9'],
    #      ['47','d9','e8','59'],
    #      ['0c','b7','ad','d6'],
    #      ['af','7f','67','98']]

    # w =[['60','3d','eb','10'],
    #     ['15','ca','71','be'],
    #     ['2b','73','ae','f0'],
    #     ['85','7d','77','81'],
    #     ['1f','35','2c','07'],
    #     ['3b','61','08','d7'],
    #     ['2d','98','10','a3'],
    #     ['09','14','df','f4']]

    Nk = len(w)


    for i in range(Nk, 4 * (Nr + 1)):
        temp = []
        temp.extend(w[i - 1])

        if i % Nk == 0:
            temp = RCon(SubWord(RotWord(temp)), Nk, i)
        elif Nk > 6 and i % Nk == 4:
            temp = SubWord(temp)


        newLine = ["","","",""]

        for l in range(4):
            newLine[l] = hex(int(temp[l], 16)^int(w[i-Nk][l], 16)).split('x')[1]
            if len(newLine[l]) == 1:
                newLine[l] ="0" + newLine[l]

        temp = []
        for i in newLine:
            temp.append(i)
        w.append(newLine)

    return w