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
        self.letter_frequency = [   0.065, 0.012, 0.022, 0.032, 0.103, 0.019, 0.015,
                                    0.049, 0.055, 0.001, 0.005, 0.033, 0.020, 0.057,
                                    0.063, 0.017, 0.001, 0.051, 0.067, 0.090, 0.027,
                                    0.010, 0.024, 0.002, 0.020, 0.001]

    def decode(self, file: str)-> tuple:
        '''
        Decode a ciphertext using the Vigenere cipher. Find the key to the plaintext.

        Args:
            file (str): File path with the ciphertext.

        Return:
            Key used in the encryption process and the plaintext.
        '''
        print("File: %s" % (file))
        start = time()
        ciphertext = self.get_ciphertext(file)
        parameters = self.get_parameters(ciphertext)
        key = self.get_key(parameters)
        plaintext = self.decrypt(ciphertext, key)
        self.save_plaintext(file, plaintext)
        end = time()
        print("Execution time: %.5f" % (end-start))
        return key, plaintext

    def get_ciphertext(self, file: str)-> str:
        '''
        Reads the file where the ciphertext is placed.

        Args:
            file (str): File path with the ciphertext.

        Return:
            The ciphertext without any whitespaces.
        '''
        ciphertext = ""
        if isfile(file):
            with open("%s" % (file), "r") as f:
                ciphertext = f.read()
            ciphertext = self.remove_whitespace(ciphertext)
        else:
            exit("File not found")
        return ciphertext

    def remove_whitespace(self, text: str)-> str:
        '''
        Removes white spaces from the string received as a parameter.

        Args:
            text (str): A plaintext or ciphertext that you want to ensure the removal
                of whitespaces.

        Return:
            String with no whitespace.
        '''
        return text.replace(" ", "")

    def get_parameters(self, ciphertext: str)-> dict:
        '''
        Analyzes the ciphertext to obtain the text index of coincidence, the key size,
        and the number of times each letter is repeated in the text. 20 iterations are
        performed, increasing the key size guess by 1 each round. The highest match
        index found is stored.
        Note: Matching indexes of equal value are disregarded, as the keyword is
        repeated 1 time or more.

        Args:
            ciphertext (str): A string that you want to perform the analysis of the
                index of coincidence and related parameters.

        Return:
            A dictionary with the parameters of the index of coincidence analysis, being
            the parameters "ioc" for the index of coincidence, "key_length" for the key
            length, and "letter_counts" for the number of times each letter is
            repeated in the text.
        '''
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
        '''
        Calculates the arithmetic mean and returns the value with 3 decimal places.

        Args:
            lst (list): a list of int or float values.

        Return:
            A float as a result of the weighted average of the received list of int
            and/or float.
        '''
        return round(float(sum(lst)/len(lst)), 3)

    def index_coincidence(self, ciphertext: str, key_length: int)-> tuple:
        '''
        Performs analysis of the received string to obtain the index of coincidence,
        evaluating the key length received as a parameter.

        Args:
            ciphertext (str): String that you want to get the IOC.
            key_length (int): Key size guess, string will be divided into n lists for
                IOC calculation.

        Return:
            .
        '''
        ioc = []
        ciphertext_splitted = self.ciphertext_splitter(ciphertext, key_length)
        letter_counts = self.letters_counter(ciphertext_splitted)
        n = len(ciphertext_splitted[0])
        total = self.summation(letter_counts)
        for i in total:
            ioc.append(float(i) / ((n * (n - 1))))
        return ioc, letter_counts

    def ciphertext_splitter(self, ciphertext: str, key_length: int)-> list:
        '''
        Divides the received string into n lists, according to the length key received
        as a parameter.

        Args:
            ciphertext (str): String that you want to split into n parts.
            key_length (int): Number of parts you want to split the string.

        Return:
            List of n lists containing the split string.
        '''
        ciphertext_lists = []
        for i in range(key_length):
            ciphertext_lists.append([])
            for j in range(0, len(ciphertext), key_length):
                if i+j >= len(ciphertext):
                    break
                ciphertext_lists[i].append(ord(ciphertext[i+j]))
        return ciphertext_lists

    def letters_counter(self, ciphertext_splitted: list)-> list:
        '''
        Performs the analysis of how many times each letter is repeated in the string,
        for each of the received strings.

        Args:
            ciphertext_splitted (list): A list of strings.

        Return:
            A list with the number of times each of the 26 letters were repeated in the
            text, considering index "0" the letter "a", index 1 the letter "b" and so
            on, until index "25" letter "z ".
        '''
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
        '''
        Performs the sum of the received value list.

        Args:
            letter_counts (list): List of values to be summed.

        Return:
            Returns the sum of values from the n lists received as a parameter.
        '''
        total = []
        idx = 0
        for counts in letter_counts:
            total.append(0)
            for ni in counts:
                total[idx] += ni * (ni - 1)
            idx += 1
        return total

    def get_key(self, parameters: dict)-> str:
        '''
        Based on the analysis of the index of coincidence, the process of comparing the
        letter that is most repeated in the ciphertext and which letter is most repeated
        in the analyzed language is carried out to obtain the key.

        Args:
            parameters (dict): dictionary with the parameters of the analysis of the
                index of coincidence, but only "letter_counts" is used, for frequency
                analysis of the letter that is most repeated in the ciphertext with the
                letter that is most repeated in the language of the analyzed text.

        Return:
            String of most likely string used as key.
        '''
        key = []
        readable_key = ''
        letter_counts = parameters.get("letter_counts", [])
        letter_ioc = self.letter_frequency
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
        '''
        Decoding the ciphertext using the Vigenere cipher using the discovered key.

        Args:
            ciphertext (str): Ciphertext using Vigenere cipher.
            key (list): Probable key used in text encryption.

        Return:
            The plaintext decrypted
        '''
        plain_ascii = []
        cipher_ascii = [ord(letter) for letter in ciphertext]
        for i in range(len(cipher_ascii)):
            decrypted = ((cipher_ascii[i]-key[i % len(key)]) % self.alphabet_size) +97
            plain_ascii.append(decrypted)
        plaintext = ''.join(chr(i) for i in plain_ascii)
        return plaintext

    def save_plaintext(self, file: str, plaintext: str)-> None:
        '''
        Stores the plaintext obtained in the decryption process..

        Args:
            file (str): Path where you want to store the file.
            plaintext (str): Cleartext obtained in the decryption process.

        Return:
            None
        '''
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
