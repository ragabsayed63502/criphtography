import sys
from PyQt5.QtWidgets import QInputDialog,QApplication, QMainWindow, QWidget, QPushButton, QVBoxLayout, QHBoxLayout, QComboBox, QLabel, QFileDialog, QTextEdit
from PyQt5.QtGui import QTextCursor
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import string
import numpy as np
# from  ciphers import CaesarCipher, AffineCipher, HillCipher, TripleDESCipher
class CaesarCipher:
    @staticmethod
    def encrypt(plaintext, key):
        ciphertext = ""
        for char in plaintext:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                encrypted_char = chr((ord(char) - ascii_offset + key) % 26 + ascii_offset)
                ciphertext += encrypted_char
            else:
                ciphertext += char
        return ciphertext

    @staticmethod
    def decrypt(ciphertext, key):
        plaintext = ""
        for char in ciphertext:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                decrypted_char = chr((ord(char) - ascii_offset - key) % 26 + ascii_offset)
                plaintext += decrypted_char
            else:
                plaintext += char
        return plaintext
    
class AffineCipher:
    def __init__(self):
        self.alphabet = string.ascii_uppercase
        self.modulo = len(self.alphabet)

    def encrypt(self, plaintext, key_a, key_b):
        ciphertext = ""
        for char in plaintext:
            if char.isalpha():
                char_index = self.alphabet.index(char.upper())
                encrypted_index = (key_a * char_index + key_b) % self.modulo
                encrypted_char = self.alphabet[encrypted_index]
                ciphertext += encrypted_char
            else:
                ciphertext += char
        return ciphertext

    def decrypt(self, ciphertext, key_a, key_b):
        plaintext = ""
        key_a_inverse = self._find_inverse(key_a)
        for char in ciphertext:
            if char.isalpha():
                char_index = self.alphabet.index(char.upper())
                decrypted_index = (key_a_inverse * (char_index - key_b)) % self.modulo
                decrypted_char = self.alphabet[decrypted_index]
                plaintext += decrypted_char
            else:
                plaintext += char
        return plaintext

    def _find_inverse(self, key):
        for x in range(1, self.modulo):
            if (key * x) % self.modulo == 1:
                return x
        raise ValueError("Key 'a' is not invertible.")




#                       Hill       Cipher
def encrypt(plain_text, key):
    cipher_text = ""
    block_size =  int(len(key) ** (0.5))
    key = [ ord(ch) - ord('a')  for ch in key ]
    K = np.array(key).reshape(block_size,block_size)
    print(f"Key:\n{K}\n\n")
    if (np.linalg.det(K)==0):
        return "Key is not invertiable"
    # Fill plain text with 'z' if necessary
    while len(plain_text)%block_size!=0:
        plain_text+= 'z'
    # Convert plain text to a matrix
    plain_text = [ ord(ch) - ord('a') for ch in plain_text ]
    P = np.array(plain_text).reshape(len(plain_text)//block_size,block_size)
    P = P.T
    print(f"Plain Text:\n{P}\n\n")
    # Encryption
    C = (np.dot(K,P))%26
    # Convert result matrix to cipher text
    C = C + ord('a')

    for c in range(len(C[0])):
        for r in range(len(C)):
            cipher_text+= chr(C[r][c])
    return cipher_text

def mod_inv(matrix, modulus):
        # Find the determinant of the matrix
        det = int(np.round(np.linalg.det(matrix)))
        # Find the inverse of the determinant modulo modulus
        det_inv = pow(det, -1, modulus)
        # Find the adjoint of the matrix
        adj = np.round(det * np.linalg.inv(matrix)).astype(int)
        # Find the modular multiplicative inverse of the matrix
        # (det_inv * adj)%26
        return np.mod(det_inv * adj, modulus)

def decrypt(cipher_text, key):
        plain_text = ""
        block_size =  int(len(key) ** (0.5))

        # Generate Key Matrix
        key = [ ord(ch) - ord('a')  for ch in key ]
        K = np.array(key).reshape(block_size,block_size)
        inv_K = mod_inv(K,26)
        print(f"Inverse Key:\n{inv_K}\n\n")
        
        # Convert cipher text to a matrix
        cipher_text = [ ord(ch) - ord('a') for ch in cipher_text ]
        C = np.array(cipher_text).reshape(len(cipher_text)//block_size,block_size)
        C = C.T
        print(f"Cipher Text:\n{C}\n\n")

        # Encryption
        P = (np.dot(inv_K,C))%26
        
        # Convert result matrix to cipher text
        P = P + ord('a')
        for c in range(len(P[0])):
            for r in range(len(P)):
                plain_text+= chr(int(P[r][c]))
        return plain_text


    
    # Define the decryption function

    
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Encryption and Decryption')
        self.setGeometry(100, 100, 400, 200)
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.encrypt_button = QPushButton('Encryption')
        self.decrypt_button = QPushButton('Decryption')

        hbox1 = QHBoxLayout()
        hbox1.addWidget(self.encrypt_button)
        hbox1.addWidget(self.decrypt_button)

        self.central_widget.setLayout(hbox1)

        self.encrypt_button.clicked.connect(self.show_encryption_page)
        self.decrypt_button.clicked.connect(self.show_decryption_page)

        self.show()

    def show_encryption_page(self):
        self.plaintext_label = QLabel('Plaintext: ')
        self.plaintext_textbox = QTextEdit()
        self.plaintext_textbox.setReadOnly(True)
        self.plaintext_textbox.setMaximumHeight(100)

        self.choose_method_label = QLabel('Encryption Method: ')
        self.choose_method_combobox = QComboBox()
        self.choose_method_combobox.addItem('Caesar Cipher')
        self.choose_method_combobox.addItem('3DES Cipher')
        self.choose_method_combobox.addItem('Affine Cipher')
        self.choose_method_combobox.addItem('Hill Cipher')

        self.import_button = QPushButton('Import Text File')
        self.import_button.clicked.connect(self.import_plaintext)

        self.encrypt_button = QPushButton('Encrypt')
        self.encrypt_button.clicked.connect(self.encrypt_plaintext)

        hbox2 = QHBoxLayout()
        hbox2.addWidget(self.choose_method_label)
        hbox2.addWidget(self.choose_method_combobox)

        vbox = QVBoxLayout()
        vbox.addWidget(self.plaintext_label)
        vbox.addWidget(self.plaintext_textbox)
        vbox.addLayout(hbox2)
        vbox.addWidget(self.import_button)
        vbox.addWidget(self.encrypt_button)

        widget = QWidget()
        widget.setLayout(vbox)

        self.setCentralWidget(widget)

    def show_decryption_page(self):
        self.ciphertext_label = QLabel('Ciphertext: ')
        self.ciphertext_textbox = QTextEdit()
        self.ciphertext_textbox.setReadOnly(True)
        self.ciphertext_textbox.setMaximumHeight(100)

        self.choose_method_label = QLabel('Decryption Method: ')
        self.choose_method_combobox = QComboBox()
        self.choose_method_combobox.addItem('Caesar Cipher')
        self.choose_method_combobox.addItem('3DES Cipher')
        self.choose_method_combobox.addItem('Affine Cipher')
        self.choose_method_combobox.addItem('Hill Cipher')

        self.import_button = QPushButton('Import Text File')
        self.import_button.clicked.connect(self.import_ciphertext)

        self.decrypt_button = QPushButton('Decrypt')
        self.decrypt_button.clicked.connect(self.decrypt_ciphertext)

        hbox2 = QHBoxLayout()
        hbox2.addWidget(self.choose_method_label)
        hbox2.addWidget(self.choose_method_combobox)

        vbox = QVBoxLayout()
        vbox.addWidget(self.ciphertext_label)
        vbox.addWidget(self.ciphertext_textbox)
        vbox.addLayout(hbox2)
        vbox.addWidget(self.import_button)
        vbox.addWidget(self.decrypt_button)

        widget = QWidget()
        widget.setLayout(vbox)

        self.setCentralWidget(widget)

    def import_plaintext(self):
        file_name, _ = QFileDialog.getOpenFileName(self, 'Import Text File',
                                                    '', 'Text Files (*.txt)')
        if file_name:
            with open(file_name, 'r') as file:
                self.plaintext_textbox.setText(file.read())


    def import_ciphertext(self):
        file_name, _ = QFileDialog.getOpenFileName(self, 'Import Text File',
                                                '', 'Text Files (*.txt)')
        if file_name:
            with open(file_name, 'r') as file:
                self.ciphertext_textbox.setPlainText(file.read())




    


    def encrypt_plaintext(self):
        plaintext = self.plaintext_textbox.toPlainText()
        method = self.choose_method_combobox.currentText()

        if method == 'Caesar Cipher':
            key, ok_pressed = QInputDialog.getInt(self, "Enter Key", "Key:", 3, 0, 25, 1)
            if ok_pressed:
                caesar_cipher = CaesarCipher()
                ciphertext = caesar_cipher.encrypt(plaintext,key)
                self.plaintext_textbox.setPlainText('')
                self.plaintext_textbox.setPlainText(ciphertext)
                with open('output.txt', 'w') as output_file:
                     output_file.write(ciphertext)


        elif method == 'Affine Cipher':
            a, ok1 = QInputDialog.getInt(self, "Enter value for 'a' (must be coprime with 26)", "a:", 3, 1, 25, 1)
            b, ok2 = QInputDialog.getInt(self, "Enter value for 'b'", "b:", 7, 0, 25, 1)
            if ok1 and ok2:
                affine_cipher = AffineCipher()
                ciphertext = affine_cipher.encrypt(plaintext,a,b)
                self.plaintext_textbox.setPlainText('')
                self.plaintext_textbox.setPlainText(ciphertext)
                with open('output.txt', 'w') as output_file:
                     output_file.write(ciphertext)

        elif method == 'Hill Cipher':
            key,ok_pressed = QInputDialog.getText(self, "Enter Key", "Key:")
            if ok_pressed:
                try:
                    # key = "gybnqkurp"
                    print(key)
                    # print(plaintext)
                    # hill_cipher = HillCipher()
                    # ciphertext = hill_cipher.encrypt(plaintext , key)
                    ciphertext = encrypt(plaintext , key)
                    self.plaintext_textbox.setPlainText('')
                    self.plaintext_textbox.setPlainText(ciphertext)
                    with open('output.txt', 'w') as output_file:
                     output_file.write(ciphertext)
                except ValueError:
                    self.show_error_message('Invalid Key')

        elif method == '3DES Cipher':
            # key1, ok1 = QInputDialog.getText(self, "Enter Key1", "Key1:")
            # if ok1:
                key = get_random_bytes(16)
                cipher = DES3.new(key, DES3.MODE_ECB)
                ciphertext = cipher.encrypt(pad(plaintext.encode(), 8))
                self.plaintext_textbox.setPlainText('')
                self.plaintext_textbox.setPlainText(ciphertext.hex())
                with open('output.txt', 'w') as output_file:
                 output_file.write(ciphertext.hex())

           


    def decrypt_ciphertext(self):
        ciphertext = self.ciphertext_textbox.toPlainText()
        method = self.choose_method_combobox.currentText()

        if method == 'Caesar Cipher':
            key, ok_pressed = QInputDialog.getInt(self, "Enter Key", "Key:", 3, 0, 25, 1)
            if ok_pressed:
                caesar_cipher = CaesarCipher()
                plaintext = caesar_cipher.decrypt(ciphertext , key)
                self.ciphertext_textbox.setPlainText('')
                self.ciphertext_textbox.setPlainText(plaintext)
                with open('output.txt', 'w') as output_file:
                     output_file.write(plaintext)

        elif method == 'Affine Cipher':
            a, ok1 = QInputDialog.getInt(self, "Enter value for 'a' (must be coprime with 26)", "a:", 3, 1, 25, 1)
            b, ok2 = QInputDialog.getInt(self, "Enter value for 'b'", "b:", 7, 0, 25, 1)
            if ok1 and ok2:
                affine_cipher = AffineCipher()
                plaintext = affine_cipher.decrypt(ciphertext,a,b)
                self.ciphertext_textbox.setPlainText('')
                self.ciphertext_textbox.setPlainText(plaintext)
                with open('output.txt', 'w') as output_file:
                     output_file.write(plaintext)

        elif method == 'Hill Cipher':
           
         # key, ok_pressed = QInputDialog.getText(self, "Enter Key", "Key:")
            key,ok_pressed = QInputDialog.getText(self, "Enter Key", "Key:")
            if ok_pressed:
                try:
                    # key_matrix = HillCipher.create_key_matrix(key)
                    # hill_cipher = HillCipher(key_matrix)
                    plaintext = decrypt(ciphertext , key)
                    self.ciphertext_textbox.setPlainText('')
                    self.ciphertext_textbox.setPlainText(plaintext)
                    with open('output.txt', 'w') as output_file:
                     output_file.write(plaintext)
                except ValueError:
                    self.show_error_dialog('Invalid key!')

        elif method == '3DES Cipher':
            
            plaintext = unpad(ciphertext.dec(ciphertext), 8)
            self.plaintext_textbox.setPlainText('')
            self.plaintext_textbox.setPlainText(plaintext)
            with open('output.txt', 'w') as output_file:
                 output_file.write(plaintext)




if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = MainWindow()
    sys.exit(app.exec_())