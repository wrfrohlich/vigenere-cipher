import time
class Vigenere():
    def __init__(self):
        self.guesses = 21
        self.alphabet_size = 26
        self.ioc_english = 0.0656
        self.ioc_portuguese = 0.0738
        self.letter_frequences = {
            'EN' : [0.065, 0.012, 0.022, 0.032, 0.103, 0.019, 0.015, 0.049, 0.055,
                    0.001, 0.005, 0.033, 0.020, 0.057, 0.063, 0.017, 0.001, 0.051,
                    0.067, 0.090, 0.027, 0.010, 0.024, 0.002, 0.020, 0.001],
            "PT" : [0.0687, 0.0150, 0.0279, 0.0463, 0.0964, 0.0157, 0.0104, 0.0129,
                    0.0654, 0.0047, 0.0002, 0.0343, 0.0252, 0.0463, 0.0974, 0.0228,
                    0.0114, 0.0664, 0.0780, 0.0433, 0.0360, 0.0153, 0.0007, 0.0021,
                    0.0001, 0.0047]
        }

    def decode(self, file: str)-> str:
        start = time.time()
        ciphertext = self.get_ciphertext(file)
        parameters = self.get_parameters(ciphertext)
        key = self.get_key(parameters)
        plaintext = self.decrypt(ciphertext, key)
        self.save_plaintext(plaintext)
        end = time.time()
        print("Execution time: %.5f" % (end-start))

    def get_ciphertext(self, file: str)-> str:
        ciphertext = ""
        with open(file, "r") as f:
            ciphertext = f.read()
        ciphertext = self.remove_whitespace(ciphertext)
        return ciphertext

    def remove_whitespace(self, text: str)-> str:
        return text.replace(" ", "")

    def get_parameters(self, ciphertext: str)-> dict:
        parameters = {}
        for key_length in range(1, self.guesses):
            ioc, letter_counts = self.index_coincidence(ciphertext, key_length)
            ioc = self.average(ioc)
            if parameters.get('ioc', 0) < ioc:
                parameters['ioc'] = ioc
                parameters['key_length'] = key_length
                parameters['letter_counts'] = letter_counts
        return parameters

    def average(self, lst: list)-> float:
        return float(sum(lst)/len(lst))

    def index_coincidence(self, ciphertext: str, key_length: int)-> tuple[list, list]:
        ioc = []
        ciphertext_splitted = self.ciphertext_splitter(ciphertext, key_length)
        letter_counts = self.letters_counter(ciphertext_splitted)
        n = len(ciphertext_splitted[0])
        total = self.summation(letter_counts)
        for i in total:
            ioc.append(float(i) / ((n * (n - 1))))
        return ioc, letter_counts

    def ciphertext_splitter(self, ciphertext: str, key_length: int)-> list:
        ciphertext_lists = []
        for i in range(key_length):
            ciphertext_lists.append([])
            for j in range(0, len(ciphertext), key_length):
                if i+j >= len(ciphertext):
                    break
                ciphertext_lists[i].append(ord(ciphertext[i+j]))
        return ciphertext_lists

    def letters_counter(self, ciphertext_splitted: list)-> list:
        idx = 0
        letter_counts = []
        for ciphertext_set in ciphertext_splitted:
            count = [0]*26
            for l in ciphertext_set:
                count[l - ord('a')] += 1
            letter_counts.append(count)
            idx += 1
        return letter_counts
    
    def summation(self, letter_counts: list)-> list:
        total = []
        idx = 0
        for counts in letter_counts:
            total.append(0)
            for ni in counts:
                total[idx] += ni * (ni - 1)
            idx += 1
        return total

    def get_key(self, parameters: dict)-> str:
        key = []
        readable_key = ''
        letter_counts = parameters.get("letter_counts", [])
        letter_ioc = self.letter_frequences.get("EN", [])
        for i in range(len(letter_counts)):
            original = letter_ioc.index(sorted(letter_ioc, reverse = True)[0])
            shifted = letter_counts[i].index(sorted(letter_counts[i], reverse = True)[0])
            shift = 1 + shifted - original
            shift = shift if shift > 0 else self.alphabet_size + shift
            key.append(shift+96)
            readable_key += chr(shift+96)
        print("Your most probably key is: %s" % readable_key)
        return key

    def decrypt(self, ciphertext: str, key: list)-> str:
        plain_ascii = []
        cipher_ascii = [ord(letter) for letter in ciphertext]
        for i in range(len(cipher_ascii)):
            decrypted = ((cipher_ascii[i]-key[i % len(key)]) % self.alphabet_size) +97
            plain_ascii.append(decrypted)
        plaintext = ''.join(chr(i) for i in plain_ascii)
        return plaintext

    def save_plaintext(self, plaintext: str)-> None:
        with open("./plaintexts/decipher.txt", "w") as f:
            f.write(plaintext)

v = Vigenere()
v.decode("./ciphertexts/cipher31.txt")
