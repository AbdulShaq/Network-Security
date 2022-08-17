import hashlib as hash

#number to letter mapping for LEET speak
num2Letter = { 'a': '4', 'e': '3', 'g': '9', 'i': '1', 'l': '1','o': '0','s': '5','t': '7' }
#symbol to letter mapping for LEET speak
Sym2Letter = { 'a': '@','e': '€', 'i': '!','s': '$','t': '+'}

############################################################################
def Leet(Type, password,Hash):#Transform any LEET speak encodings
    for key in num2Letter.keys():#transform any LEET encoding to plain text from numbers to letters
        password = password.replace(key,num2Letter[key])
    for key in Sym2Letter.keys():#transform any LEET encoding to plain text from symbol to letters
        password = password.replace(key,num2Letter[key])

     #encode and hash the corrected password based on its time
    enc_fixed = password.encode('utf-8')
    if Type == 1:
          digest = hash.md5(enc_fixed.strip()).hexdigest()
    elif Type == 2:
                 digest = hash.sha1(enc_fixed.strip()).hexdigest()
    elif Type == 3:
                digest = hash.sha256(enc_fixed.strip()).hexdigest()
    elif Type == 4:
                 digest = hash.sha512(enc_fixed.strip()).hexdigest()        
        
    if digest == Hash:#check if the currently hashed password matches the hash we have 
              print("Match found")
              print("Password is: " +password)
              return True#return true if found     
    return False #returns false if it is not found 

############################################################################
def encrypt(text,s):#Encode the password with the Caesar Cipher 
    result = ""
    # traverse text
    for i in range(len(text)):
        char = text[i]
        
        # Shift digits based on ASCII table 
        if char.isdigit():
            result += chr((ord(char) + s - 48) % 10 + 48)   
        else:# Shift Upper/Lowercase letters and the symbols inbetween based on ASCII table 
            result += chr((ord(char) + s-65) % 58 + 65)  
 
    return result#return the shifted cipher

def Caesar(Type,Password,Hash): 

   x =0
   while x <= 56:
     result = encrypt(Password,x)#Caesar chipher shift the password x shifts
    
     #encode and hash the corrected password based on its time
     Encode = result.encode('utf-8')
     if  Type == 1:
       digest = hash.md5(Encode.strip()).hexdigest()
     elif Type == 2:
             digest = hash.sha1(Encode.strip()).hexdigest()
     elif Type == 3:
              digest = hash.sha256(Encode.strip()).hexdigest()
     elif Type == 4:
             digest = hash.sha512(Encode.strip()).hexdigest()      
     
     
     if digest == Hash:#check if the currently hashed password matches the hash we have
        print("Match found")
        print("Password is: " + result)
        return True#return true if found
     x=x+1   
               
   return False #returns false if it is not found         

############################################################################
def salt( Type,Password,Hash ): #add a 5 digit SALT to the password starting with 00000 to 99999 
  Password = Password.replace("\n",'') #remove any endline characters from password so SALT can be added properly
  output = " "
  for num1 in range(9):
    for num2 in range(9):
      for num3 in range(9):
        for num4 in range(9):
          for num5 in range(9):
            i = str(num1)+str(num2)+str(num3)+str(num4)+str(num5) #make the salt
            output = "{}{}".format(Password,i) # append it to the end of the current password being tested
            
            #Encode password and hash based on the type
            Encode = output.encode('utf-8')
            if  Type == 1:
              digest = hash.md5(Encode.strip()).hexdigest()
            elif Type == 2:
                digest = hash.sha1(Encode.strip()).hexdigest()
            elif Type == 3:
                digest = hash.sha256(Encode.strip()).hexdigest()
            elif Type == 4:
                digest = hash.sha512(Encode.strip()).hexdigest()      

            if digest == Hash:#check if the currently hashed password matches the hash we have 
                print("Match found")
                print("Password with SALT is: " + output)
                return True #return true if found
      
  return False#returns false if it is not found

############################################################################
def Password_Cracker( Type, Hash_Pass):
    File = open("dictionary.txt", "r")
    for word in File: 
        enc_word  = word.encode('utf-8')
        #Try cracking the passwords without any changes/modifactions
        if Type == 1:
           digest = hash.md5(enc_word.strip()).hexdigest()
        elif Type == 2:
           digest = hash.sha1(enc_word.strip()).hexdigest()
        elif Type == 3:
           digest = hash.sha256(enc_word.strip()).hexdigest()
        elif Type == 4:
            digest = hash.sha512(enc_word.strip()).hexdigest()        

        
        if digest == Hash_Pass:
          print("Match found")
          print("Password is: " + word)
          return
          
    File = open("dictionary.txt", "r")
    for word2 in File:
        #If not solved from the easiest way then try solving with Leet speak, SALT, or Caesar Cipher
        if Leet(Type,word2,Hash_Pass)== True:
            return
        if Caesar(Type,word2,Hash_Pass) == True:
            return  
        if salt(Type,word2,Hash_Pass) == True:
            return        
       
############################################################################
def main():
    HashFile = open("shadow", "r")
    for line in HashFile:#Go through each line of the shadow.txt
        x = len(line)-1
        Hash_Pass = line[6:x]#get just the hashed password for each user from shadow text
        
        print(line[0:7])
        if len(Hash_Pass) == 32:#check if the length matches a MD5 hashing length, if it is only hash using that type
           Password_Cracker(1,Hash_Pass) 
        elif len(Hash_Pass) == 40:#check if the length matches a SHA1 hashing length, if it is only hash using that type
            Password_Cracker(2,Hash_Pass) 
        elif len(Hash_Pass) == 64:#check if the length matches a SHA256 hashing length, if it is only hash using that type
            Password_Cracker(3,Hash_Pass)
        elif len(Hash_Pass) == 128:#check if the length matches a SHA512 hashing length, if it is only hash using that type
            Password_Cracker(4,Hash_Pass)    

if __name__ == "__main__":
  main()