from funksionet import *


ciphertext = b'\xe6\xe9v&\x1aq\x8f^F\x91\x18\x86\x03]\x1f\xe3\x06\xc2\xf6\x8d\xd5,o\xad\xc4F-'
celesi = b'1234123412341234'
IV = b'6\xf0\x8ff\xc6\xf3\x11B\xf9\x1b\xf2\xc0\xa8\xbf0\xbb'
sz = 9
aes = pyaes.AESModeOfOperationCFB(celesi,iv = IV,segment_size = sz) 
decrypted = aes.decrypt(ciphertext)
print(decrypted)


def unpadded_for_decrypted_ciphertext(ciphertext,plaintext_length):
    return padded_plaintext[:plaintext_length]
