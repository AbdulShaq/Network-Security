import hashlib as hash
import  re, copy

LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
NoLetters= re.compile('[^A-Z\s]')
WordMappings = {} #Hold the mapping

def decrypt(key, Word):
    Decrypted = ''
    for char in Word: # loop through each letter in the Word
        if char.upper() in key: #decrypt the char
            charIndex = key.find(char.upper())
            if char.isupper():
                Decrypted += LETTERS[charIndex].upper()
            else:
                Decrypted += LETTERS[charIndex].lower()
        else:
            Decrypted += char# char is not in LETTERS then add it
    return Decrypted

def getPattern(word):
    # Returns a string of the pattern form of the given word.
    word = word.upper()
    NextNum = 0
    letterNums = {}
    Pattern = []
    for letter in word:
        if letter not in letterNums:
            letterNums[letter] = str(NextNum)
            NextNum += 1
        Pattern.append(letterNums[letter])

    return '.'.join(Pattern)

def FindPatterns():

    dict = open('CommonDict.txt') #Dictionary with most common english words
    wordList = dict.read().split('\n')
    dict.close()

    for word in wordList:# Get the pattern for each string in wordList.
        pattern = getPattern(word)
        if pattern not in WordMappings:
            WordMappings[pattern] = [word]
        else:
            WordMappings[pattern].append(word)
    
def getEmptyMapping():
    # Returns a dictionary value that is a blank cipherletter mapping.
    return {'A': [], 'B': [], 'C': [], 'D': [], 'E': [], 'F': [], 'G': [], 'H': [], 'I': [], 'J': [], 'K': [], 'L': [], 'M': [], 'N': [], 'O': [], 'P': [], 'Q': [], 'R': [], 'S': [], 'T': [], 'U': [], 'V': [], 'W': [], 'X': [], 'Y': [], 'Z': []}

def AddLettersToMap(letterMap, cipherWord, candidate):
    # This function adds the possible letters as potential
    # decryption letters for the cipher mapping
    letterMap = copy.deepcopy(letterMap)
    for i in range(len(cipherWord)):
        if candidate[i] not in letterMap[cipherWord[i]]:
            letterMap[cipherWord[i]].append(candidate[i])
    return letterMap

def intersectMappings(map1, map2):
    # To intersect two maps, create a blank map, and then add only the
    # potential decryption letters if they exist in BOTH maps.
    IntersectedMap = getEmptyMapping()

    for char in LETTERS:
        # An empty list means "any letter is possible". In this case just
        # copy the other map entirely.
        if map1[char] == []:
            IntersectedMap[char] = copy.deepcopy(map2[char])
        elif map2[char] == []:
            IntersectedMap[char] = copy.deepcopy(map1[char])
        else:
            for mappedLetter in map1[char]:
                if mappedLetter in map2[char]:
                    IntersectedMap[char].append(mappedLetter)

    return IntersectedMap

def removeSolvedLetters(letterMap):
    letterMap = copy.deepcopy(letterMap)
    again = True
    while again:
        again = False#assume we will not loop again

        # solved will be a list of uppercase letters that have one
        # and only one possible mapping in letterMap
        solved = []
        for cipherletter in LETTERS:
            if len(letterMap[cipherletter]) == 1:
                solved.append(letterMap[cipherletter][0])
        for cipherletter in LETTERS:
            for s in solved:
                if len(letterMap[cipherletter]) != 1 and s in letterMap[cipherletter]:
                    letterMap[cipherletter].remove(s)
                    if len(letterMap[cipherletter]) == 1:
                        # if new letter is now solved loop again.
                        again = True
    return letterMap

def HackSubCipher(Word):
    intersectedMap = getEmptyMapping()
    cipherList = NoLetters.sub('', str(Word).upper()).split()
    for cipherword in cipherList:# Get a new cipherletter mapping for each ciphertext word
        newMap = getEmptyMapping()
        wordPattern = getPattern(cipherword)
        if wordPattern not in WordMappings:# if the word was not in our dictionary then continue
            continue 
        for candidate in WordMappings[wordPattern]:
            newMap = AddLettersToMap(newMap, cipherword, candidate)
        
        intersectedMap = intersectMappings(intersectedMap, newMap)#Intersect the new mapping with the existing intersected mapping
       
    return removeSolvedLetters(intersectedMap) # Remove any solved letters from the other lists

def decryptWithCipherletterMapping(ciphertext, letterMapping):
    # Return a string of the decrypted ciphertext using the letter mapping, with any letters that have multiple mappings replaced with space
    key = ['x'] * len(LETTERS)

    for cipherletter in LETTERS:

        if len(letterMapping[cipherletter]) == 1:
            # If there's only one letter, add it to the key.
            keyIndex = LETTERS.find(letterMapping[cipherletter][0])
            key[keyIndex] = cipherletter
        else:
            ciphertext = ciphertext.replace(cipherletter.lower(), ' ')
            ciphertext = ciphertext.replace(cipherletter.upper(), ' ')

    key = ''.join(key)

    
    return decrypt(key, ciphertext)#try to decrypt with key that is made

def encryptWithCipher(PassWord):
    Mapp = 'SGQUNTIVDPEJROZHAYFCLWXMKB' #solved mapping used by user7
    encypted = ''
    
    for char in PassWord:# loop through each char in the message
        if char.upper() in LETTERS:# encrypt the char
            symIndex = LETTERS.find(char.upper())
            if char.isupper():
                encypted += Mapp[symIndex].upper()
            else:
                encypted += Mapp[symIndex].lower()
        else:
            encypted += char 

    return encypted

def User7Attack():

    File = open("dictionary.txt", "r")

    for word in File:
        HackedPass = encryptWithCipher(word)#encrypt each password in dictionary.txt with user7's
                                            #sub cipher then hash
        EncPass = HackedPass.encode('utf-8')
        digest = hash.md5(EncPass.strip()).hexdigest() #User7's hash is 32 characters long which coorilates to an MD5 hash
        if digest == '3e730e3402aa4157cedd91b50cc60f54':#check if the currently hashed password matches User7's Hash
              print("Match found")
              print("Password is: " + word)
              return

def main():
    FindPatterns()#Find the word patterns
   
    file = open("encrypted.txt","r")
    EncryptedText = file.read()
    
    letterMapping = HackSubCipher(EncryptedText) # find valid letter mapping for User7's Cipher
    print("Substitution Cipher Mapping:")
    print(letterMapping) 
    
    print("\nOriginal encrpted text:")
    print(EncryptedText)
    
    hackedMessage = decryptWithCipherletterMapping(EncryptedText, letterMapping) #Decrypt message using letter mapping
    print("\nDecrypted text:")
    print(hackedMessage)

    User7Attack() #Find user7's password
   

if __name__ == '__main__':

    main()