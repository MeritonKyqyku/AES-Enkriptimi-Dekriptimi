#AES Encryptor with Python
#Libraria e perdorur: Pyaes nga Ricmoo: https://github.com/ricmoo/pyaes
import pyaes
from funksionet import *


#vm - valido modin
#vk - valido celesin random
#vkuc - valido celesin e zgjedhur nga useri

key_list = ["128","192","256"] #madhesite e celesave ne AES
mod_list = ["ECB","CBC"] #Modet e enkriptimit
choice_celesi_list = ["R","U"]
vkuc = True #nese useri ka zgjedh celes random, vkuc gjith rri true
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
                     choice_celesi = input("A deshironi te zgjedhni nje celes apo te gjenerohet nje random? (R/U):")
                     choice_celesi = choice_celesi.upper()
                     if(choice_celesi == "R"):
                         celesi = key(int(chosen_key_size))
                     elif(choice_celesi == "U"):
                         celesi = input("Jep celesin " + str(int(int(chosen_key_size)/8)) + " bajt:")
                         vkuc = valido_key_size_user(celesi,chosen_key_size)
                     #duhet me shtu ni validim tjeter
                         
                         celesi = bytes(celesi,"utf-8")
                     
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
                            else:
                                continue
                         else:
                             print("Enkriptimi Deshtoi.")

                    
                          

                             

                     else:
                        print("Nuk keni zgjedhur asnje opsion te pershtatshem, ju lutem provoni perseri")


                          













    
   

    



