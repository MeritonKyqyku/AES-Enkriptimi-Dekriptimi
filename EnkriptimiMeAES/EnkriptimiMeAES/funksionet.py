import os
import pyaes
import re
import datetime
from Crypto import Random
#funksionet qe kemi me i perdor ne Enkriptim/Dekriptim
now = datetime.datetime.now()
def valido_celesin(key,list):
    if key in list:
       return 1
    else:
       print("Zgjedhje invalide, ju lutem zgjedheni madhesine 128, 192 apo 256")
       return 0

def valido_modin(mod,list):
    if mod in list:
       return 1
    else:
       print("Zgjedhje invalide, ju lutem zgjedheni modin ECB, CBC, CFB, CTR apo OFB")
       return 0

def valido_key_size_user(celesi,chosen_key_size):
    if(len(celesi) == int(int(chosen_key_size)/8)):
         return True
    else:
         return False

def valido_tipin(tipi,list):
    if tipi in list:
       return 1
    else:
       print("Zgjedhje invalide, ju lutem zgjedheni ENKRIPTIMIN(E) apo DEKRIPTIMIN(D)")
       return 0

def valido_zgjedhjen(zgjedhja,list):
    if zgjedhja in list:
       return 1
    else:
       print("Zgjedhje invalide, ju lutem zgjedheni TEKST (T) apo FAJLL (F)")
       return 0

def key(choice):
    if(choice == 128):
          return os.urandom(16) #16 bytes, pra 16*8 = 128 bit
    elif(choice == 192):
          return os.urandom(24) #24 bytes, pra 24*8 = 192 bit
    else:
          return os.urandom(32) #32 bytes, pra 32*8 = 256 bit

def padding(plaintext):
    while(len(plaintext) % 16 != 0):
         plaintext += "x"

    
    s = re.findall('.{1,16}', plaintext)
    return s
def unpadded(unpadded_plaintext,padded_plaintext):
    return padded_plaintext[:len(unpadded_plaintext)]

def EnkriptimiMeECB(plaintext,celesi): #Per arsye se blloqet ne ECB duhet te jene nga 16 bytes, duhet ti bejme pad
    plaintext_padded = padding(plaintext) #funksioni padding(plaintext) na kthen nje liste me secilin element nga 16-byte, ku elementi i fundit mund te kete
                                            # shkronjen "x" te shtuar si padding
    aes = pyaes.AESModeOfOperationECB(celesi) #per arsye se nuk ruhet gjendja, skemi nevoje me instancu dy here aes-in
    ciphertext = []
    decrypted = []
    ciphertext_original = []

    for i in range(len(plaintext_padded)):
     ciphertext.append(aes.encrypt(plaintext_padded[i]))
     decrypted.append(aes.decrypt(ciphertext[i]).decode("utf-8")) #Listes me elemente te dekriptuara ja bejme append elementet e dekriptuara pastaj te dekoduara
     ciphertext_original.append(ciphertext[i].decode("latin-1")) #pse 'latin-1'? Nuk e di, qashtu bojke, ndryshe sbojke

    decrypted_padded_str = ''.join(str(e) for e in decrypted) #e kthejme listen ne string
    decrypted = unpadded(plaintext,decrypted_padded_str) #ja hjekim paddingun
    ciphertext_str = ''.join(str(e) for e in ciphertext_original) #ciphertextin e kthejme ne string

    if(decrypted == plaintext):
        return ciphertext_str.encode("utf-8"), decrypted #ta-daaaa, e kem qa
    else:
        return;

def EnkriptimiMeCBC(plaintext,celesi,IV):
    plaintext_padded = padding(plaintext) #duhet me pas plaintextin 16 byte, e kemi nda ne lista me elemente nga 16 byte ku elementi i fundit munet me kan padded
    aes = pyaes.AESModeOfOperationCBC(celesi,iv = IV) #na duhet nje Initialization Vector per siguri
    ciphertext = []
    decrypted = []
    ciphertext_original = []
    for i in range(len(plaintext_padded)):
        ciphertext.append(aes.encrypt(plaintext_padded[i]))
        ciphertext_original.append(ciphertext[i].decode("latin-1")) #apet, nuk e di pse 'latin-1', qashtu bojke.

    ciphertext_str = ''.join(str(e) for e in ciphertext_original)
    aes = pyaes.AESModeOfOperationCBC(celesi,iv = IV) #Nuk ruhet gjendja ne CBC! Per kete arsye na duhet me instancu dy here
    for i in range(len(plaintext_padded)):
        decrypted.append(aes.decrypt(ciphertext[i]).decode("utf-8"))

    decrypted_padded_str = ''.join(str(e) for e in decrypted) # e kthejme ne string
    decrypted = unpadded(plaintext,decrypted_padded_str) #ja hjekum paddingun

    if(decrypted == plaintext):
        return ciphertext_str.encode("utf-8"), decrypted
    else:
        return;


def DekriptimiMeECB(ciphertext,celesi): #PADDED
    decrypted = []
    decrypted_1 = []
    aes = pyaes.AESModeOfOperationECB(celesi)
    ciphertext_list = re.findall('.{1,16}', ciphertext.decode('utf-8'))
    for i in range(len(ciphertext_list)):
        decrypted.append(aes.decrypt(ciphertext_list[i]))
        decrypted_1.append(decrypted[i].decode("utf-8"))
    decrypted_padded_str = ''.join(str(e) for e in decrypted_1)
    return decrypted_padded_str

def DekriptimiMeCBC(ciphertext,celesi,IV):#PADDED
    aes = pyaes.AESModeOfOperationCBC(celesi,iv = IV) 
    ciphertext_list = re.findall('.{1,16}', ciphertext.decode('utf-8'))
    decrypted = []
    decrypted_1 = []
    for i in range(len(ciphertext_list)):
            decrypted.append(aes.decrypt(ciphertext_list[i]))
            decrypted_1.append(decrypted[i].decode("utf-8"))


    decrypted_padded_str = ''.join(str(e) for e in decrypted_1)

    return decrypted_padded_str

def SegmentSizeMultiple(plaintext, segment_size):
    while(len(plaintext) % int(segment_size) != 0): #na vyn per te modi CFB
        plaintext += "x"

    return plaintext



def rezultati(celesi, plaintext, ciphertext, decrypted):
    print("Enkriptimi mbaroi me sukses.")
    print("\nPlaintexti:" + str(plaintext))
    print("\nCelesi:" + str(celesi) + "Ne formatin unicode")
    print("\nCelesi:" + str(celesi.decode('latin-1')))
    print("\nCiphertexti:" + str(ciphertext) + "ne formatin unicode")
    print("\nCiphertexti:" + str(ciphertext.decode('latin-1')))
    print("\nPlaintexti:" + str(decrypted))
   
def save_it_1b(ciphertext,celesi,chosen_mod,length,Emri):
    

    year = now.year
    month = now.month
    day = now.day
    hour = now.hour
    minute = now.minute
    second = now.second
    microsecond = now.microsecond
    data =  Emri
    path_ciphertext = r'C:\Users\Meriton Kycyku\Desktop\EnkriptimiMeAES\Encrypted_Plaintext\C' + data + "[" + str(chosen_mod) + "]" +".txt"
    path_key = r'C:\Users\Meriton Kycyku\Desktop\EnkriptimiMeAES\Encrypted_Plaintext\K' + data + "[" + str(chosen_mod) + "]" +".txt"
    path_length = r'C:\Users\Meriton Kycyku\Desktop\EnkriptimiMeAES\Encrypted_Plaintext\P' + data + "[" + str(chosen_mod) + "]" +".txt"
    with open(path_ciphertext, "wb") as fc:
        fc.write(ciphertext)
        fc.close()
    with open(path_key, "wb") as fk:
        fk.write(celesi)
        fk.close()
    with open(path_length, "wb") as fl:
        fl.write(length)
        fl.close()
    if(os.path.exists(path_ciphertext) and os.path.exists(path_key) and os.path.exists(path_length)):
        print("\nRuajtja ishte e sukseshme")
    else:
        print("\nRuajtja deshtoi")


def save_it_2b(ciphertext,celesi, IV,chosen_mod,length,Emri):
    

    year = now.year
    month = now.month
    day = now.day
    hour = now.hour
    minute = now.minute
    second = now.second
    microsecond = now.microsecond
    data =Emri
    path_ciphertext = r'C:\Users\Meriton Kycyku\Desktop\EnkriptimiMeAES\Encrypted_Plaintext\C' + data + "[" + str(chosen_mod) + "]" +".txt"
    path_key = r'C:\Users\Meriton Kycyku\Desktop\EnkriptimiMeAES\Encrypted_Plaintext\K' + data + "[" + str(chosen_mod) + "]" +".txt"
    path_iv = r'C:\Users\Meriton Kycyku\Desktop\EnkriptimiMeAES\Encrypted_Plaintext\V' + data +  "[" + str(chosen_mod) + "]" +".txt"
    path_length = r'C:\Users\Meriton Kycyku\Desktop\EnkriptimiMeAES\Encrypted_Plaintext\l' + data + "[" + str(chosen_mod) + "]" +".txt"
    with open(path_ciphertext, "wb") as fc:
        fc.write(ciphertext)
        fc.close()
    with open(path_key, "wb") as fk:
        fk.write(celesi)
        fk.close()
    with open(path_iv, "wb") as fiv:
        fiv.write(IV)
        fiv.close()
    with open(path_length, "wb") as fl:
        fl.write(length)
        fl.close()

    if(os.path.exists(path_ciphertext) and os.path.exists(path_key) and os.path.exists(path_iv) and os.path.exists(path_length)):
        print("\nRuajtja ishte e sukseshme")
    else:
        print("\nRuajtja deshtoi")




def unpadded_for_decrypted(decrypted,plaintext_length):
    return decrypted[:plaintext_length]