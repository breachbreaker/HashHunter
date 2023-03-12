# Import the required libraries
from pwn import *
import argparse

# Define a function to crack a password hash
def crack_hash(hash_type, wanted_hash, password_list):
    attempts = 0

    # Show progress while attempting to crack the hash
    with log.progress("Attempting to Crack: {}!\n".format(wanted_hash)) as p:
        # Open the password list file
        with open(password_list, "r", encoding='latin-1') as passwords:
            # Loop through each password in the file
            for password in passwords:
                # Strip any newline characters from the password and encode it as bytes
                password = password.strip("\n").encode('latin-1')
                # Hash the password using the specified hash algorithm
                if hash_type == 'sha256':
                    password_hash = sha256sumhex(password)
                elif hash_type == 'md5':
                    password_hash = md5sumhex(password)
                elif hash_type == 'sha1':
                    password_hash = sha1sumhex(password)
                else:
                    # If an invalid hash algorithm is specified, print an error message and return
                    print('Invalid hash type')
                    return

                # Show progress by printing the password being tried and the hash it generates
                p.status("[{}] {} == {}".format(attempts, password.decode('latin-1'), password_hash))
                # If the generated hash matches the hash we want to crack, print the password and return it
                if password_hash == wanted_hash:
                    p.success("Password found after {} attempts! {} hashes to {}!".format(attempts, password.decode('latin-1'), password_hash))
                    return password.decode('latin-1')
                # Increment the number of attempts and try the next password
                attempts += 1

        # If we reach the end of the password list without finding the password, print a failure message and return None
        p.failure("Password hash not found!")
        return None

# This block of code runs if this script is called directly from the command line
if __name__ == '__main__':
    # Define command line arguments for the hash type, hash file, and password file
    parser = argparse.ArgumentParser(description='Hash Hunter')
    parser.add_argument('-t', required=True, choices=['sha256', 'md5', 'sha1'], help='type of hash to crack')
    parser.add_argument('-f', required=True, help='file containing list of hashes')
    parser.add_argument('-p', required=True, help='file containing list of passwords')
    args = parser.parse_args()

    # Store the command line arguments in variables for later use
    hash_type = args.t
    hash_file = args.f
    password_file = args.p

    # Open the file containing the hashes we want to crack
    with open(hash_file, 'r') as hashes:
        # Loop through each hash in the file and try to crack it
        for hash in hashes:
            hash = hash.strip('\n')
            crack_hash(hash_type, hash, password_file)
