################################################################################
#
# CREATED                           : ON THE 19TH NOVEMBER 2014
# UPDATED                           : ON 7 DECEMBER 2014 @ 23:27 HRS
# CREATED BY                        : EGBIE ANDERSON
# PROGRAM NAME                      : ENCRYPTOR
# PURPOSE                           : TO ENCRYPT AND DECRYPT FILES
# ENCRYPTION ALGORITHM              : AES 256
# OPERATING SYSTEM                  : ANY LINUX BASED OPERATING SYSTEM
#
# PROGRAM DESCRIPTION
# ===============
#
# A SIMPLE SCRIPT THAT ENCRYPTS OR DECRYPTS
# A FILE. THE PROGRAM USES OPENSSL WITH AN AES ALGORITHM TO
# ENCRYPT OR DECRYPTS FILES. ONCE THE FILES HAS BEEN
# ENCRYPTED THE ORIGINAL UNENCRYPTED FILES IS SECURELY
# DELETED. THIS IS DONE BY SHREDDING THE FILES X-AMOUNT OF TIMES.
#
# THE SCRIPT CAN ENCRYPT MOST DOCUMENTS INCLUDING WORD
# FILES SUCH AS .ODT, DOCX, DOC, TEXT DOCUMENTS, ETC
#
# COPYRIGHT 2014
###############################################################################

import optparse
import platform
import webbrowser
import re
import os
import sys
from os import system, geteuid, system, getcwd
from time import sleep
          
class Encryptor(object):
    """
    This program allows the user to take any file and using an AES algorithm
    to either encrypt or decrypt a file. When a file is encrypted or decrypted
    the the original file is shredded. 
    """
    
    def _is_file_name_legal(self, orig_file, new_file):
        """_is_file_name_legal(str, str) -> return(tuple)

        Verifies whether the input is legal, verifies whether a file exists, removes any
        spaces that is contained in the original file.

        Returns a tuple if the parameters are met or exits if the parameters
        are not met.
        """
        
        if not os.path.exists(orig_file) : sys.exit("[+] The file could not be located, exiting program!!!")
        
        self.new_file = re.findall("\w+\.\w+", new_file)  # a single word without spaces plus file extenstion
        
        # Remove spaces in the original filename to prevent openssl from throwing a fit
        if  " " in orig_file:
            
            print "\n[+] Spaces detected in original file name."
            print "[+] Replacing spaces with an underscore in order to prevent openssl from malfuncting, please wait .. "
            print "[+] Renaming original file on hard drive to new file name, please wait.."
            
            new_file_name = orig_file.replace(" ", "_")                 # replace spaces with an underscore
            os.rename(orig_file, new_file_name)                         # rename file on the hard drive to new file name
            orig_file = new_file_name

            print "[+] Spaces replaced with underscore complete."
            print "[+] File re-name on hard drive complete.\n"
            
        return (orig_file, "".join(self.new_file)) if self.new_file else sys.exit("[!] Enter a name for the new file")
         
           
    def _delete_file(self, file_to_delete, num):
        """secure deletes a file from the hard drive by shredding it n times"""

        while True:
            self.answer = raw_input("\n[+] Attemping to delete %s file this will " \
                                                     "erase the file permantly continue (y/n) : "%(file_to_delete)).lower()
            if self.answer == "y":
                
                print "[+] please wait, begin process..\n"
                print "[+] The file will be over written %d times ..."%(num)
                sleep(2)
                system("shred -u %s -n %d -v" %(file_to_delete, num))            # run this command directly on the OS
                print "\n[+] Done the file %s has successfully being shredded" %(file_to_delete)
                break
            
            elif self.answer == "n":
                
                print "\n[+]  Warning the file was not deleted"
                print "If you have used Encrypter to encrypt a file. The unencrypted file can be used to retreive your data"
                break
            
            else: 
                print "The answer must either (y or n) "

    def _translate(self, mode, orig_file, new_file, num):
        '''_translate(str, str, str, int) -> return(bool)
        A wrapper function that gives additonal help to the encrypt and decrypt method
        '''
        self.orig_file, self.new_file = self._is_file_name_legal(orig_file, new_file)
        system("%s -in %s -out %s" %(mode, self.orig_file, self.new_file))

        # if the new file does not exists it means something went wrong and the file was
        # not encrypted/decrypted. In that case the script exists otherwise the delete
        # method is activated and the file is shredded.
        if not os.path.exists(self.new_file):
            print("\n[+] Encrypter was unable to successful encrypt\decrypt the file !!!\n")
            return False
        
        self._delete_file(self.orig_file, num)
        return True

    def encrypt(self, mode, filename, new_filename, num):
        """encrypt(str, str, str, int) -> return(Void)
        Encrypts a file returns True if encryption was
        successful and false otherwise
        """
        return self._translate(mode, filename, new_filename, num)

    def decrypt(self, mode, filename, new_filename, num):
        """decrypt(str, str, str, int) -> returns(void)
        Decrypts a file returns True if decryption was
        successful and false otherwise
        """
        return self._translate(mode, filename, new_filename, num)

    def _open_file(self, message, file_to_open, value):
        '''_open_file(str, str) -> returns(void)
        Opens a file on the user hard drive.
        '''
        if value:
            print("\n[+] The file has be %sed please wait opening %sed file.." %(message, message))
            sleep(1)

            # Openssl stores the encrypted/decrypted file in the CWD. Encryptor ensures
            # that that open method will be able to open the file no matter what file path the user enters.
            webbrowser.open(os.path.basename(file_to_open)) 
            print("[+] Done, have a nice day.")
        
# the main program
def main():

    encryption = "openssl aes-256-cbc -a -salt"  # the encryption method used to encrypt the file
    decryption = "openssl aes-256-cbc -a -d"     # the decryption method used to decrypt the file
       
    # the command line argument
    parser = optparse.OptionParser("\n[!] usage%prog -m <encrypted or decrypted> "\
                                   " -s <no of times to shred the file > -f <filename to encrypt or decrypt> -n <new_filename> \n")
    
    parser.add_option("-m", dest = "file_mode", type = "string", help = "enter the file state either or 'encrypt' or 'decrypt'")
    parser.add_option("-s", dest = "shred_no", type = "int", help = "enter the number of times you want to shred the file")
    parser.add_option("-f", "--file", dest = "current_file", type = "string", help = "enter the file to be encrypted or decrypted")
    parser.add_option("-n", "--new_filename", dest = "new_filename", type = "string", help = "enter the new filename to be used for the new file")
    (options, args) = parser.parse_args()

    file_mode, shred_no, curr_file, new_file = options.file_mode, options.shred_no, options.current_file, options.new_filename
    
    if (not file_mode) and (not shred_no) and (not curr_file) and (not new_file): sys.exit(parser.usage)
    else:
        if file_mode == "encrypt":
            
            value = encrypter.encrypt(encryption, curr_file, new_file, shred_no)
            encrypter._open_file("encrypt", new_file, value)
     
        elif file_mode == "decrypt":
            
            value = encrypter.encrypt(decryption, curr_file, new_file, shred_no)
            encrypter._open_file("decrypt", new_file, value)
        else:
            print(parser.usage)
    
# when the program is not imported this part of the program is executed
if __name__ == "__main__":

    operating_system = platform.system()
    user_uid= geteuid()   # get the user uid if it is equal to 0 then user is root and if 1000 then the user is a normal user
    
    if  not os.path.exists("/usr/bin/openssl"):
        print("\n[+] Encryptor has detected that there is no openssl on your system")

       
        if (operating_system == "Linux") and (not user_uid):
            answer = raw_input("[+] Encryptor can install the program do you want to continue (y/n) : ")
            if (answer.lower() == "y"):
                system("sudo apt-get install openssl")
            else:
                sys.exit("\n[!] The program need openssl to continue .. exiting program")
        elif operating_system != "Linux": sys.exit("[!] You need to be running on a linux system, closing program")
        elif (operating_system == "Linux") and  (not user_uid) : sys.exit("[!] run this program as root or log in with root prividles to install openssl")

    encrypter = Encryptor()
    main()
