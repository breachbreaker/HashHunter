# HashHunter
HashHunter is a command-line tool for cracking password hashes using a list of possible passwords. The script supports three types of hash functions: SHA256, MD5, and SHA1. 

Given a file containing a list of hashes and a file containing a list of possible passwords, HashHunter attempts to crack each hash and print the password if successful. The script uses the popular Pwntools library for handling binary data and network connections, and the built-in Argparse module for parsing command-line arguments. 

HashHunter is based on the sha256 hash cracker Python script from [TCM academy's Python 101 Course](https://academy.tcm-sec.com/p/python-101-for-hackers) and I have  added the following.


- Allow the user to specify the hash type to crack (SHA256, MD5, or SHA1).
- Allow the user to specify the hash file to use as input.
- Allow the user to specify the password file to use as input.
- Error handling to check if the files exist and if the script has read permissions on them.
- Can crack multiple hashes at once from a hash file.

# Hash Hunter
Hash Hunter is a Python script for cracking various types of password hashes. It currently supports SHA-256, MD5, and SHA-1 hashes.

## Prerequisites
The following dependencies are required to run Hash Hunter:

- pwntools
- argparse

To install pwntools and argparse, run the following command:

```python
pip3 install pwntools argparse
```

## Usage
To run Hash Hunter, use the following command:

```python
python hash_hunter.py -t [hash_type] -f [hash_file] -p [password_file]
```

Where:

- **hash_type** is the type of hash to crack (sha256, md5, or sha1)
- **hash_file** is the file containing a list of hashes to crack, one per line
- **password_file** is the file containing a list of passwords to use for cracking the hashes, one per line

Example usage:

```python
python hash_hunter.py -t sha256 -f hashes.txt -p passwords.txt
```


