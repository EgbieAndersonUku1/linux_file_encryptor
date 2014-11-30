###############################################################################
#
# CREATED ON THE 19TH NOVEMBER 2014
# CREATED BY EGBIE ANDERSON
# PROGRAM NAME: ENCRYPTOR
# PURPOSE: TO ENCRYPT FILES
# OPERATING SYSTEM: ANY LINUX BASED OPERATING SYSTEM
#
# PROGRAM DESCRIPTION
# ======================
#
# A SIMPLE SCRIPT THAT ENCRYPTS OR DECRYPTS
# A FILE. THE PROGRAM USES OPENSSL WITH AN AES ALGORITHM TO
# ENCRYPT OR DECRYPTS FILES. ONCE THE FILES HAS BEEN
# ENCRYPTED THE ORIGINAL UNENCRYPTED FILES IS SECURELY
# DELETED. THIS IS DONE BY SHREDDING THE FILES X-AMOUNT OF TIMES.
#
# THE PROGRAM CAN ENCRYPT MOST DOCUMENTS INCLUDING WORD
# FILES, EXCEL DOCUMENTS, TEXT DOCUMENTS, ETC
#
# COPYRIGHT 2014
# THE SCRIPT IS FREE TO BE MODIFIED WITHOUT MY PERMISSION
###############################################################################

import optparse
import platform
import webbrowser
import re
import os
import sys
from os import system, listdir, geteuid, system, getcwd
from time import sleep
          
class Encryptor(object):
    """This program allows the user to take any file and using an aes algorithm
    encrypts the file deleting the orignal unencrypted file. The user can also use
    the program to decrypt the file."""
    
    def verify_input(self, filename1, new_filename):
        """verify_input(str, str) -> return(str)
        Verifies whether the input is legal
        """
        
        if not self.does_file_exists(filename1): sys.exit("[+] The file does not exists")
        else:
            self.new_filename = re.findall("\w+\.\w+", new_filename)  # a single word without spaces plus file extenstion
            if new_filename:
                return (filename1, "".join(self.new_filename))
            else:
                sys.exit("[!] You must enter a filename both for the encrypted and plain file")
         
    def does_file_exists(self, file_name):
        """does_file_exists(str) -> return(value)
        Checks whether the file specifed by the user exits
        Returns True if it does exists the program if it does not
        """      
        return True if os.path.exists(file_name) else sys.exit("The file does not exist")
        
    def delete_file(self, file_to_be_deleted, num):
        """secure deletes a file from the hard drive by shredding it n times"""

        while True:
            self.answer = raw_input("\n[+] Attemping to delete %s file this will " \
                                  "erase the file permantly continue (y/n) : "%(file_to_be_deleted))
            if self.answer == "y":
                print("[+] please wait, begin process..\n")
                print("[+] The file will be over written %d times ..."%(num))
                sleep(2)
                system("shred -u %s -n %d -v" %(file_to_be_deleted, num))
                print("\n[+] Done %s text file shredded" %(file_to_be_deleted))
                break
            elif self.answer == "n": sys.exit("\n[+] The file will not be deleted, exiting program !")
            else: 
                print("The answer must either (y or n) ")

    def _translate(self, mode, filename, new_filename, num):
        '''translate(str, str, str, int) -> return(void)
        A wrapper function that gives additonal help to the encrypt and decrypt method
        '''
        self.filename, self.second_filename = self.verify_input(filename, new_filename)
        system(" %s -in %s -out %s " %(mode, self.filename, self.second_filename))
        self.delete_file(self.filename, num)

    def encrypt(self, mode, filename, new_filename, num):
        """Encrypts a file"""
        self._translate(mode, filename, new_filename, num)

    def decrypt(self, mode, filename, new_filename, num):
        """Decrypts a file"""
        self._translate(mode, filename, new_filename, num)
 
# the main program
def main():

    encryption = "openssl aes-256-cbc -a -salt" # the encryption method used to encrypt the file
    decryption = "openssl aes-256-cbc -a -d"    # the decryption method used to decrypt the file
       
    # the command line argument
    parser = optparse.OptionParser("\n[!] usage%prog -m <encrypted or decrypted> "\
                                   " -s <no of times to shred the file > -f <filename to encrypt or decrypt> -n <new_filename> \n")
    
    parser.add_option("-m", dest = "file_mode", type = "string", help = "enter the file state either or 'encrypt' or 'decrypt'")
    parser.add_option("-s", dest = "shred_no", type = "int", help = "enter the number of times you want to shred the file")
    parser.add_option("-f", "--file", dest = "current_file", type = "string", help = "enter the file to be encrypted or decrypted")
    parser.add_option("-n", "--new_filename", dest = "new_filename", type = "string", help = "enter the new filename to be used for the new file")
    (options, args) = parser.parse_args()

    file_mode, shred_no, curr_file, new_file = options.file_mode, options.shred_no, options.current_file, options.new_filename
    
    if (file_mode == None) and (shred_no == None) and (curr_file == None) and (new_file == None): sys.exit(parser.usage)
    else:
        if file_mode == "encrypt":
            encrypter.encrypt(encryption, curr_file, new_file, shred_no)
            print("\n[+] The file has be encrypted please wait opening encrypted file..")
            sleep(1)
            webbrowser.open(new_file)
            print "[+] Done"
     
        elif file_mode == "decrypt":
            encrypter.decrypt(decryption, curr_file, new_file, shred_no)
            print("\n[+] The file has be decrypted please wait opening decrypted file..")
            sleep(1)
            webbrowser.open(new_file)
            print "[+] Done"
        else:
            print(parser.usage)
    
# when the program is not imported this part of the program is executed
if __name__ == "__main__":

    operating_system = platform.system()
    user = geteuid() # get the user uid if it is equal to 0 then user is root and if 1000 then the user is a normal user
    
    if  not os.path.exists("/usr/bin/openssl"):
        print("\n[+] The program has detected that there is no openssl on your system")
        
        if operating_system == "Linux" and user == 0:
            answer = raw_input("Encryptor can install the program do you want to continue (y/n) : ")
            if (answer.lower() == "y"):
                system("sudo apt-get install openssl")
            else:
                sys.exit("\n[!] The program need openssl to continue .. exiting program")
        elif operating_system != "Linux": sys.exit("[!] You need to be running on a linux system, closing program")
        elif operating_system == "Linux" and user != 0: sys.exit("[!] run this program as root or log in with root prividgles to install openssl")

    encrypter = Encryptor()
    main()
