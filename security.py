import math

# 全局常量，与 JavaScript 一致
biRadixBase = 2
biRadixBits = 16
bitsPerDigit = biRadixBits
biRadix = 1 << 16  # 65536
biHalfRadix = biRadix >> 1
biRadixSquared = biRadix * biRadix
maxDigitVal = biRadix - 1

# 初始化最大位数和零数组
maxDigits = 0
ZERO_ARRAY = []

def setMaxDigits(value):
    global maxDigits, ZERO_ARRAY
    maxDigits = value
    ZERO_ARRAY = [0] * maxDigits

# 大整数类
class BigInt:
    def __init__(self, flag=None):
        if isinstance(flag, bool) and flag:
            self.digits = None
        else:
            self.digits = ZERO_ARRAY.copy()
        self.isNeg = False

    def __str__(self):
        return f"{'-' if self.isNeg else ''}{''.join(map(str, self.digits[::-1]))}"

# Barrett 约减类，用于高效模运算
class BarrettMu:
    def __init__(self, modulus):
        self.modulus = BigInt()
        self.modulus.digits = modulus.digits.copy()
        self.k = biHighIndex(self.modulus) + 1
        b2k = BigInt()
        if 2 * self.k < maxDigits:
            b2k.digits[2 * self.k] = 1
        else:
            raise ValueError("2 * k exceeds maxDigits")
        self.mu = biDivide(b2k, self.modulus)  # 修改处：去掉 [0]
        self.bkplus1 = BigInt()
        if self.k + 1 < maxDigits:
            self.bkplus1.digits[self.k + 1] = 1
        else:
            raise ValueError("k + 1 exceeds maxDigits")

    def modulo(self, x):
        q1 = biDivideByRadixPower(x, self.k - 1)
        q2 = biMultiply(q1, self.mu)
        q3 = biDivideByRadixPower(q2, self.k + 1)
        r1 = biModuloByRadixPower(x, self.k + 1)
        r2term = biMultiply(q3, self.modulus)
        r2 = biModuloByRadixPower(r2term, self.k + 1)
        r = biSubtract(r1, r2)
        if r.isNeg:
            r = biAdd(r, self.bkplus1)
        while biCompare(r, self.modulus) >= 0:
            r = biSubtract(r, self.modulus)
        return r

    def multiplyMod(self, x, y):
        xy = biMultiply(x, y)
        return self.modulo(xy)

    def powMod(self, x, y):
        result = BigInt()
        result.digits[0] = 1
        a = BigInt()
        a.digits = x.digits.copy()
        k = BigInt()
        k.digits = y.digits.copy()
        while True:
            if k.digits[0] & 1:
                result = self.multiplyMod(result, a)
            k = biShiftRight(k, 1)
            if k.digits[0] == 0 and biHighIndex(k) == 0:
                break
            a = self.multiplyMod(a, a)
        return result

# RSA 密钥对类
class RSAKeyPair:
    def __init__(self, encryptionExponent, decryptionExponent, modulus):
        self.e = biFromHex(encryptionExponent)
        self.d = biFromHex(decryptionExponent) if decryptionExponent else BigInt()
        self.m = biFromHex(modulus)
        self.chunkSize = 2 * biHighIndex(self.m)
        self.radix = 16
        self.barrett = BarrettMu(self.m)

# RSA 工具类
class RSAUtils:
    @staticmethod
    def getKeyPair(encryptionExponent, decryptionExponent, modulus):
        return RSAKeyPair(encryptionExponent, decryptionExponent, modulus)

    @staticmethod
    def encryptedString(key, s):
        a = [ord(c) for c in s]
        while len(a) % key.chunkSize != 0:
            a.append(0)
        al = len(a)
        result = ""
        for i in range(0, al, key.chunkSize):
            block = BigInt()
            j = 0
            for k in range(i, i + key.chunkSize, 2):
                block.digits[j] = a[k]
                if k + 1 < i + key.chunkSize:
                    block.digits[j] += a[k + 1] << 8
                j += 1
            crypt = key.barrett.powMod(block, key.e)
            text = biToHex(crypt)
            result += text + " "
        return result.strip()

# 大整数运算函数
def biFromHex(s):
    result = BigInt()
    sl = len(s)
    for i, j in zip(range(sl, 0, -4), range(maxDigits)):
        start = max(i - 4, 0)
        result.digits[j] = hexToDigit(s[start:i])
    return result

def hexToDigit(s):
    result = 0
    for i in range(min(len(s), 4)):
        result <<= 4
        result |= charToHex(ord(s[i]))
    return result

def charToHex(c):
    if 48 <= c <= 57:  # 0-9
        return c - 48
    elif 97 <= c <= 122:  # a-z
        return 10 + c - 97
    elif 65 <= c <= 90:  # A-Z
        return 10 + c - 65
    return 0

def biToHex(x):
    result = ""
    for i in range(biHighIndex(x), -1, -1):
        result += digitToHex(x.digits[i])
    return result

def digitToHex(n):
    mask = 0xf
    result = ""
    for _ in range(4):
        result = hexToChar[n & mask] + result
        n >>= 4
    return result

hexToChar = "0123456789abcdef"

def biHighIndex(x):
    result = len(x.digits) - 1
    while result > 0 and x.digits[result] == 0:
        result -= 1
    return result

def biAdd(x, y):
    result = BigInt()
    c = 0
    for i in range(len(x.digits)):
        n = x.digits[i] + y.digits[i] + c
        result.digits[i] = n % biRadix
        c = 1 if n >= biRadix else 0
    result.isNeg = x.isNeg
    return result

def biSubtract(x, y):
    if x.isNeg != y.isNeg:
        y.isNeg = not y.isNeg
        result = biAdd(x, y)
        y.isNeg = not y.isNeg
    else:
        result = BigInt()
        c = 0
        for i in range(len(x.digits)):
            n = x.digits[i] - y.digits[i] + c
            result.digits[i] = n % biRadix
            if result.digits[i] < 0:
                result.digits[i] += biRadix
            c = -1 if n < 0 else 0
        if c == -1:
            c = 0
            for i in range(len(x.digits)):
                n = 0 - result.digits[i] + c
                result.digits[i] = n % biRadix
                if result.digits[i] < 0:
                    result.digits[i] += biRadix
                c = -1 if n < 0 else 0
            result.isNeg = not x.isNeg
        else:
            result.isNeg = x.isNeg
    return result

def biMultiply(x, y):
    result = BigInt()
    n = biHighIndex(x)
    t = biHighIndex(y)
    c = 0
    for i in range(t + 1):
        c = 0
        k = i
        for j in range(n + 1):
            uv = result.digits[k] + x.digits[j] * y.digits[i] + c
            result.digits[k] = uv & maxDigitVal
            c = uv >> biRadixBits
            k += 1
        result.digits[i + n + 1] = c
    result.isNeg = x.isNeg != y.isNeg
    return result

def biDivide(x, y):
    return biDivideModulo(x, y)[0]

def biDivideModulo(x, y):
    nb = biNumBits(x)
    tb = biNumBits(y)
    origYIsNeg = y.isNeg
    if nb < tb:
        if x.isNeg:
            q = BigInt()
            q.digits[0] = 1
            q.isNeg = not y.isNeg
            x.isNeg = False
            y.isNeg = False
            r = biSubtract(y, x)
            x.isNeg = True
            y.isNeg = origYIsNeg
        else:
            q = BigInt()
            r = BigInt()
            r.digits = x.digits.copy()
        return [q, r]

    q = BigInt()
    r = BigInt()
    r.digits = x.digits.copy()

    t = math.ceil(tb / bitsPerDigit) - 1
    lambda_ = 0
    while y.digits[t] < biHalfRadix:
        y = biShiftLeft(y, 1)
        lambda_ += 1
        tb += 1
        t = math.ceil(tb / bitsPerDigit) - 1

    r = biShiftLeft(r, lambda_)
    nb += lambda_
    n = math.ceil(nb / bitsPerDigit) - 1

    b = biMultiplyByRadixPower(y, n - t)
    while biCompare(r, b) != -1:
        q.digits[n - t] += 1
        r = biSubtract(r, b)

    for i in range(n, t, -1):
        ri = r.digits[i] if i < len(r.digits) else 0
        ri1 = r.digits[i - 1] if i - 1 < len(r.digits) else 0
        ri2 = r.digits[i - 2] if i - 2 < len(r.digits) else 0
        yt = y.digits[t] if t < len(y.digits) else 0
        yt1 = y.digits[t - 1] if t - 1 < len(y.digits) else 0
        if ri == yt:
            q.digits[i - t - 1] = maxDigitVal
        else:
            q.digits[i - t - 1] = (ri * biRadix + ri1) // yt

        c1 = q.digits[i - t - 1] * (yt * biRadix + yt1)
        c2 = (ri * biRadixSquared) + (ri1 * biRadix + ri2)
        while c1 > c2:
            q.digits[i - t - 1] -= 1
            c1 = q.digits[i - t - 1] * (yt * biRadix + yt1)
            c2 = (ri * biRadixSquared) + (ri1 * biRadix + ri2)

        b = biMultiplyByRadixPower(y, i - t - 1)
        r = biSubtract(r, biMultiplyDigit(b, q.digits[i - t - 1]))
        if r.isNeg:
            r = biAdd(r, b)
            q.digits[i - t - 1] -= 1

    r = biShiftRight(r, lambda_)
    q.isNeg = x.isNeg != origYIsNeg
    if x.isNeg:
        q = biAdd(q, BigInt()) if origYIsNeg else biSubtract(q, BigInt())
        q.digits[0] = 1
        y = biShiftRight(y, lambda_)
        r = biSubtract(y, r)
    if r.digits[0] == 0 and biHighIndex(r) == 0:
        r.isNeg = False
    return [q, r]

def biMultiplyDigit(x, y):
    result = BigInt()
    n = biHighIndex(x)
    c = 0
    for j in range(n + 1):
        uv = result.digits[j] + x.digits[j] * y + c
        result.digits[j] = uv & maxDigitVal
        c = uv >> biRadixBits
    result.digits[n + 1] = c
    return result

def biShiftLeft(x, n):
    digitCount = n // bitsPerDigit
    result = BigInt()
    arrayCopy(x.digits, 0, result.digits, digitCount, len(result.digits) - digitCount)
    bits = n % bitsPerDigit
    rightBits = bitsPerDigit - bits
    for i in range(len(result.digits) - 1, 0, -1):
        result.digits[i] = ((result.digits[i] << bits) & maxDigitVal) | \
                           ((result.digits[i - 1] & highBitMasks[bits]) >> rightBits)
    result.digits[0] = (result.digits[0] << bits) & maxDigitVal
    result.isNeg = x.isNeg
    return result

def biShiftRight(x, n):
    digitCount = n // bitsPerDigit
    result = BigInt()
    arrayCopy(x.digits, digitCount, result.digits, 0, len(x.digits) - digitCount)
    bits = n % bitsPerDigit
    leftBits = bitsPerDigit - bits
    for i in range(len(result.digits) - 1):
        result.digits[i] = (result.digits[i] >> bits) | \
                           ((result.digits[i + 1] & lowBitMasks[bits]) << leftBits)
    result.digits[-1] >>= bits
    result.isNeg = x.isNeg
    return result

def biMultiplyByRadixPower(x, n):
    result = BigInt()
    arrayCopy(x.digits, 0, result.digits, n, len(result.digits) - n)
    return result

def biDivideByRadixPower(x, n):
    result = BigInt()
    arrayCopy(x.digits, n, result.digits, 0, len(result.digits) - n)
    return result

def biModuloByRadixPower(x, n):
    result = BigInt()
    arrayCopy(x.digits, 0, result.digits, 0, n)
    return result

def biCompare(x, y):
    if x.isNeg != y.isNeg:
        return 1 - 2 * int(x.isNeg)
    for i in range(len(x.digits) - 1, -1, -1):
        if x.digits[i] != y.digits[i]:
            return 1 - 2 * int(x.digits[i] > y.digits[i]) if x.isNeg else 1 - 2 * int(x.digits[i] < y.digits[i])
    return 0

def biNumBits(x):
    n = biHighIndex(x)
    d = x.digits[n]
    m = (n + 1) * bitsPerDigit
    for result in range(m, m - bitsPerDigit, -1):
        if d & 0x8000:
            break
        d <<= 1
    return result

def arrayCopy(src, srcStart, dest, destStart, n):
    m = min(srcStart + n, len(src))
    for i, j in zip(range(srcStart, m), range(destStart, len(dest))):
        dest[j] = src[i]

highBitMasks = [0x0000, 0x8000, 0xC000, 0xE000, 0xF000, 0xF800, 0xFC00, 0xFE00,
                0xFF00, 0xFF80, 0xFFC0, 0xFFE0, 0xFFF0, 0xFFF8, 0xFFFC, 0xFFFE, 0xFFFF]

lowBitMasks = [0x0000, 0x0001, 0x0003, 0x0007, 0x000F, 0x001F, 0x003F, 0x007F,
               0x00FF, 0x01FF, 0x03FF, 0x07FF, 0x0FFF, 0x1FFF, 0x3FFF, 0x7FFF, 0xFFFF]

# 主加密函数
def encryptPassword(password, publicKeyExponent, publicKeyModulus, macString="111111111"):
    passwordMac = password + ">" + macString
    passwordEncode = passwordMac[::-1]  # 反转字符串
    setMaxDigits(400)
    key = RSAUtils.getKeyPair(publicKeyExponent, "", publicKeyModulus)
    return RSAUtils.encryptedString(key, passwordEncode)

# 测试代码
if __name__ == "__main__":
    publicKeyExponent = "10001"
    publicKeyModulus = "94dd2a8675fb779e6b9f7103698634cd400f27a154afa67af6166a43fc26417222a79506d34cacc7641946abda1785b7acf9910ad6a0978c91ec84d40b71d2891379af19ffb333e7517e390bd26ac312fe940c340466b4a5d4af1d65c3b5944078f96a1a51a5a53e4bc302818b7c9f63c4a1b07bd7d874cef1c3d4b2f5eb7871"
    password = "xxxxxxxx"
    mac = '087f6112e7a49b1f1947921f0abcd3bf'
    encrypted = encryptPassword(password, publicKeyExponent, publicKeyModulus, mac)
    print(f"Encrypted password: {encrypted}")