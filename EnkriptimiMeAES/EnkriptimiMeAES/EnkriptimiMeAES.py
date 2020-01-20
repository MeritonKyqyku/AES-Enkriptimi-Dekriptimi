#AES Encryptor with Python
#Libraria e perdorur: Pyaes nga Ricmoo: https://github.com/ricmoo/pyaes
import pyaes
import os
from funksionet import *


#vm - valido modin
#vk - valido celesin random
#vkuc - valido celesin e zgjedhur nga useri

key_list = ["128","192","256"] #madhesite e celesave ne AES
mod_list = ["ECB","CBC"] #Modet e enkriptimit
choice_celesi_list = ["R","U"]
vkuc = True #nese useri ka zgjedh celes  random, vkuc gjith rri true
print("                                       ------------------------------------")
print("                                       |  AES Enkriptuesi dhe Dekriptuesi |")
print("                                       ------------------------------------\n")
print("                                                   Pershendetje \n\n")
lloji=input("Jepni se qfar deshironi te beni. Shtypni 'e' per enkriptim dhe 'd' per dekriptim :")
clear = lambda: os.system('cls')
clear()
if ((lloji=="e")or( lloji=="E")):
   while(True):
    print("                                           --------------------")
    print("                                           |  AES Enkriptuesi |")
    print("                                           --------------------")
    chosen_key_size = input("Zgjedheni madhesine e Celesit (128,192,256):")
    vk = valido_celesin(chosen_key_size,key_list) #valido_celesin kthen vleren 1 apo 0,  nese vlera eshte 1 vazhdohet me validimet tjera
    if(vk == 1): 
         chosen_mod = input("Zgjedheni modin(ECB,CBC):")
         chosen_mod = chosen_mod.upper()
         vm = valido_modin(chosen_mod,mod_list) #valido_modin kthen vleren 1 apo 0,  nese vlera eshte 1 vazhdohet me validimet tjera
         if(vm == 1):
                     print("Keni zgjedhur opsionet si ne vijim \nMadhesia e Celesit:"
                          + chosen_key_size + "\nModi i zgjedhur:" + chosen_mod)
                     
                     celesi = key(int(chosen_key_size))
                                      
                     mod = chosen_mod
       
                     IV = Random.get_random_bytes(16)

                     
                     if(mod == "ECB" and vkuc): #Electronic Code Book
                          plaintext = input("Plaintexti:")
                          length = bytes(str(len(plaintext)),"utf-8")
                          ciphertext,decrypted = EnkriptimiMeECB(plaintext,celesi)
                          if(plaintext == decrypted):
                             rezultati(celesi,plaintext,ciphertext,decrypted)
                             ruajtja = input("Deshironi ti ruani rezultatet? (P,J):")
                             ruajtja = ruajtja.upper()
          
                             print(ciphertext)
                             print(celesi)
                             if(ruajtja == "P"):
                                 Emri=input("Jepni Emrin e file-it :")
                                 save_it_1b(ciphertext,celesi,chosen_mod,length,Emri)
                                 print("Enkriptimi eshte kryer me sukses")
                                 quit()
                             else:
                                 continue
                     
                     
    
                     elif(mod == "CBC" and vkuc): #Cipher Block Chain
                         plaintext = input("Plaintexti:")
                         length = bytes(str(len(plaintext)),"utf-8")
                         ciphertext,decrypted = EnkriptimiMeCBC(plaintext,celesi,IV)
                         if(plaintext == decrypted):
                            rezultati(celesi,plaintext,ciphertext,decrypted)
                            print("\nIV:" + str(IV))
                            ruajtja = input("Deshironi ti ruani rezultatet? (P,J):")
                            ruajtja = ruajtja.upper()
                        
                            print(ciphertext)
                            print(celesi)
                            print(IV)
                            if(ruajtja == "P"):
                                Emri=input("Jepni Emrin e file-it :")
                                save_it_2b(ciphertext,celesi,IV,chosen_mod,length,Emri)
                                print("Enkriptimi eshte kryer me sukses")
                                quit()
                            else:
                               
                                continue
                         else:
                             print("Enkriptimi Deshtoi.")
                     else:
                        print("Nuk keni zgjedhur asnje opsion te pershtatshem, ju lutem provoni perseri")

elif((lloji=="d")or(lloji=="D")):
                    while(True):
                        print("                                           --------------------")
                        print("                                           |  AES Dekriptuesi |")
                        print("                                           --------------------")
                        mod_list = ["ECB","CBC"] #Modet e dekriptimit
                        mod = input("Zgjedheni modin(ECB,CBC):")
                        mod =  mod.upper()
                        mod_validation = valido_modin(mod,mod_list)
                        if(mod_validation == 1):
                            ciphertext_file_name = input("Jepni emrin e fajllit qe ciphertextin:\n\t")
                            celesi_file_name = input("Jepni emrin e fajllit qe permban celesin:\n\t")
                            ciphertext_file_path = r'C:\Users\Meriton Kycyku\Desktop\EnkriptimiMeAES\Encrypted_Plaintext\\' + ciphertext_file_name + ".txt" #per ta lexuar ciphertextin, eshte hardcoded po ska lidhje
                            celesi_file_path = r'C:\Users\Meriton Kycyku\Desktop\EnkriptimiMeAES\Encrypted_Plaintext\\' + celesi_file_name + ".txt"#per ta lexuar celesin, eshte hardcoded po ska lidhje
                            fciphertext = open(ciphertext_file_path, "rb") #hapet fajlli qe permban ciphertextin
                            fkey = open(celesi_file_path,"rb")#hapet fajlli qe permban celesin

                            celesi = fkey.read() #lexohet fajlli qe permban celesin
                            ciphertext = fciphertext.read()#lexohet fajlli qe permban ciphertextin
        
       


        
                            if(mod == "ECB"):
                                 decrypted = DekriptimiMeECB(ciphertext,celesi)
                                 l_file_name = input("Jepni emrin e fajllit qe permban gjatesine e plaintekstit:\n\t")
                                 l_file_path = r'C:\Users\Meriton Kycyku\Desktop\EnkriptimiMeAES\Encrypted_Plaintext\\' + l_file_name + ".txt"
                                 fl = open(l_file_path,"rb")
                                 l = fl.read()
                                 l = int(l) #l na duhet per arsye te hjekjes se shkronjave qe i kemi bere pad ekstra
                                 print("Plaintexti i dekriptuar:" + unpadded_for_decrypted(decrypted,l))
                            elif(mod == "CBC"):
                                IV_file_name = input("Jepni emrin e fajllit qe permban Vektorin Inicializues:\n\t")
                                IV_file_path = r'C:\Users\Meriton Kycyku\Desktop\EnkriptimiMeAES\Encrypted_Plaintext\\' + IV_file_name + ".txt"
                                fiv = open(IV_file_path,"rb")
                                IV = fiv.read()
                                l_file_name = input("Jepni emrin e fajllit qe permban gjatesine e plaintekstit:\n\t")
                                l_file_path = r'C:\Users\Meriton Kycyku\Desktop\EnkriptimiMeAES\Encrypted_Plaintext\\' + l_file_name + ".txt"
                                fl = open(l_file_path,"rb")
                                l = fl.read()
                                l = int(l)#l na duhet per arsye te hjekjes se shkronjave qe i kemi bere pad ekstra
                                decrypted = DekriptimiMeCBC(ciphertext,celesi,IV)
                                print("Plaintexti i dekriptuar:" + unpadded_for_decrypted(decrypted,l))
                                quit()
        
       
                        else:
                            print("Nuk keni zgjedhur mod valid, ju lutem provoni perseri (ECB,CBC)")
                            continue

else:
    print("vetem 'e' dhe 'd' jane inpute te lejushme")
     

     













    
   

    





