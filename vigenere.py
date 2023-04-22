from sys import argv
from time import time
from os import listdir, mkdir
from os.path import isdir, isfile

class Vigenere():
    def __init__(self):
        self.guesses = 21
        self.path_plain = "./plaintexts/"
        self.alphabet_size = 26
        self.ioc_english = 0.0656
        self.ioc_portuguese = 0.0738
        self.letter_frequences = [  0.065, 0.012, 0.022, 0.032, 0.103, 0.019, 0.015,
                                    0.049, 0.055, 0.001, 0.005, 0.033, 0.020, 0.057,
                                    0.063, 0.017, 0.001, 0.051, 0.067, 0.090, 0.027,
                                    0.010, 0.024, 0.002, 0.020, 0.001]

    def decode(self, file: str)-> str:
        print("File: %s" % (file))
        start = time()
        ciphertext = self.get_ciphertext(file)
        parameters = self.get_parameters(ciphertext)
        key = self.get_key(parameters)
        plaintext = self.decrypt(ciphertext, key)
        self.save_plaintext(file, plaintext)
        end = time()
        print("Execution time: %.5f" % (end-start))

    def get_ciphertext(self, file: str)-> str:
        ciphertext = ""
        if isfile(file):
            with open("%s" % (file), "r") as f:
                ciphertext = f.read()
            ciphertext = self.remove_whitespace(ciphertext)
        else:
            exit("File not found")
        return ciphertext

    def remove_whitespace(self, text: str)-> str:
        return text.replace(" ", "")

    def get_parameters(self, ciphertext: str)-> dict:
        parameters = {}
        for key_length in range(1, self.guesses):
            ioc, letter_counts = self.index_coincidence(ciphertext, key_length)
            ioc = self.average(ioc)
            best_ioc = parameters.get('ioc', 0)
            if (best_ioc < ioc) and (best_ioc / ioc != 1):
                parameters['ioc'] = ioc
                parameters['key_length'] = key_length
                parameters['letter_counts'] = letter_counts
        parameters['language'] = "PT" if parameters.get('ioc', 0) > 0.07 else "EN"
        print("The most likely language is: %s" % parameters.get('language', "EN"))
        return parameters

    def average(self, lst: list)-> float:
        return round(float(sum(lst)/len(lst)), 3)

    def index_coincidence(self, ciphertext: str, key_length: int):
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
        letter_ioc = self.letter_frequences
        for i in range(len(letter_counts)):
            original = letter_ioc.index(sorted(letter_ioc, reverse = True)[0])
            shifted = letter_counts[i].index(sorted(letter_counts[i], reverse = True)[0])
            shift = 1 + shifted - original
            shift = shift if shift > 0 else self.alphabet_size + shift
            key.append(shift+96)
            readable_key += chr(shift+96)
        print("Your most likely key is: %s" % readable_key)
        return key

    def decrypt(self, ciphertext: str, key: list)-> str:
        plain_ascii = []
        cipher_ascii = [ord(letter) for letter in ciphertext]
        for i in range(len(cipher_ascii)):
            decrypted = ((cipher_ascii[i]-key[i % len(key)]) % self.alphabet_size) +97
            plain_ascii.append(decrypted)
        plaintext = ''.join(chr(i) for i in plain_ascii)
        return plaintext

    def save_plaintext(self, file: str, plaintext: str)-> None:
        file = file.split("/")
        if not isdir(self.path_plain):
            mkdir(self.path_plain)
        with open("%s%s" % (self.path_plain, file[-1]), "w") as f:
            f.write(plaintext)

if __name__ == '__main__':
    v = Vigenere()
    if len(argv) == 1:
        path_cipher = "./ciphertexts/"
        files = listdir(path_cipher)
        for filename in files:
            file = "%s%s" % (path_cipher, filename)
            v.decode(file)
            print()
    else:
        v.decode(argv[1])
        print()
