linux_encryptor
===============

The script is a command line program that takes any file and using openssl a program that is
install on every linux box encryts or decrypts the file

commands
=======

-m (mode) : The mode of encryption to use for the file takes either "encrypt" or "decrypt"
-s (shred) : The amount of times to shred the file. Note once shred the original file is unrecoverable so
             make sure that you know your password for the decryption.
-f (file): The file to encrypt or decrypt
-n (new file) : The name for the new file

How to use the commands
========================

Linux
========

python linux_encryptor.py -m <mode> -s <number of times to shred file> -f <file> -n <new file name>

warning
==========
Make sure that you remember the password for decryption because the original file will be shredded and
depending on the number of times you requested. This makes the original file unrecoverable.



