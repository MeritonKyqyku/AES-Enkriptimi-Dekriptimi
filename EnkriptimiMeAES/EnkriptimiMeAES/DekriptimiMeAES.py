#AES Decryptor with Python
#Libraria e perdorur: Pyaes nga Ricmoo: https://github.com/ricmoo/pyaes
import pyaes
from funksionet import *
from Crypto import Random



while(True):
    print("                                           --------------------")
    print("                                           |  AES Dekriptuesi |")
    print("                                           --------------------")
    mod_list = ["ECB","CBC"] #Modet e dekriptimit
    mod = input("Zgjedheni modin(ECB,CBC):")
    mod =  mod.upper()
    mod_validation = valido_modin(mod,mod_list)
    if(mod_validation == 1):
        ciphertext_file_name = input("Jepni emrin e fajllit qe ciphertextin:")
        celesi_file_name = input("Jepni emrin e fajllit qe permban celesin:")
        ciphertext_file_path = r'C:\Users\Meriton Kycyku\Desktop\EnkriptimiMeAES\Encrypted_Plaintext\\' + ciphertext_file_name + ".txt" #per ta lexuar ciphertextin, eshte hardcoded po ska lidhje
        celesi_file_path = r'C:\Users\Meriton Kycyku\Desktop\EnkriptimiMeAES\Encrypted_Plaintext\\' + celesi_file_name + ".txt"#per ta lexuar celesin, eshte hardcoded po ska lidhje
        fciphertext = open(ciphertext_file_path, "rb") #hapet fajlli qe permban ciphertextin
        fkey = open(celesi_file_path,"rb")#hapet fajlli qe permban celesin

        celesi = fkey.read() #lexohet fajlli qe permban celesin
        ciphertext = fciphertext.read()#lexohet fajlli qe permban ciphertextin
        
       


        
        if(mod == "ECB"):
             decrypted = DekriptimiMeECB(ciphertext,celesi)
             l_file_name = input("Jepni emrin e fajllit qe permban gjatesine e plaintekstit:")
             l_file_path = r'C:\Users\Meriton Kycyku\Desktop\EnkriptimiMeAES\Encrypted_Plaintext\\' + l_file_name + ".txt"
             fl = open(l_file_path,"rb")
             l = fl.read()
             l = int(l) #l na duhet per arsye te hjekjes se shkronjave qe i kemi bere pad ekstra
             print("Plaintexti i dekriptuar:" + unpadded_for_decrypted(decrypted,l))
        elif(mod == "CBC"):
            IV_file_name = input("Jepni emrin e fajllit qe permban Vektorin Inicializues:")
            IV_file_path = r'C:\Users\Meriton Kycyku\Desktop\EnkriptimiMeAES\Encrypted_Plaintext\\' + IV_file_name + ".txt"
            fiv = open(IV_file_path,"rb")
            IV = fiv.read()
            l_file_name = input("Jepni emrin e fajllit qe permban gjatesine e plaintekstit:")
            l_file_path = r'C:\Users\Meriton Kycyku\Desktop\EnkriptimiMeAES\Encrypted_Plaintext\\' + l_file_name + ".txt"
            fl = open(l_file_path,"rb")
            l = fl.read()
            l = int(l)#l na duhet per arsye te hjekjes se shkronjave qe i kemi bere pad ekstra
            decrypted = DekriptimiMeCBC(ciphertext,celesi,IV)
            print("Plaintexti i dekriptuar:" + unpadded_for_decrypted(decrypted,l))
        
       
    else:
        print("Nuk keni zgjedhur mod valid, ju lutem provoni perseri (ECB,CBC)")
        continue

    
    


   



  
                