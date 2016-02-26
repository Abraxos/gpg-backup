#!/usr/bin/python3

from argparse import ArgumentParser
from getpass import getpass
from subprocess import check_output, Popen, PIPE
from os import listdir, remove
from os.path import join, basename, isfile, isdir


def random_filename(length=32):
    cmd = "cat /dev/urandom | tr -cd 'a-f0-9' | head -c {0}".format(length)
    output = check_output(cmd, shell=True)
    return str(output, "utf-8") + '.gpg'


def encrypt_file(src_file_path, dst_file_path, passphrase):
    # Run the GPG command to make a symmetrically encrypted version of the file at the destination
    print('ENCRYPTING FILE:\n\tSRC: {0}\n\tDST:{1}'.format(src_file_path, dst_file_path))
    cmd = ['gpg', '--yes', '--passphrase-fd', '0', '--output', dst_file_path, '--symmetric', src_file_path]
    process = Popen(cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE)
    gpg_stdout = process.communicate(input=passphrase)[0]


def decrypt_file(src_file_path, dst_file_path, passphrase):
    # Run the GPG command to decrypt a symmetrically encrypted file and write the results to a destination
    print('DECRYPTING FILE:\n\tSRC: {0}\n\tDST:{1}').format(src_file_path, dst_file_path))
    cmd = ['gpg', '--yes', '--passphrase-fd', '0', '--output', dst_file_path, '--decrypt', src_file_path]
    process = Popen(cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE)
    gpg_stdout = process.communicate(input=passphrase)[0]


def transfer_encrypted_file(file_path, remote_user, remote_url, remote_port, remote_dir):
    # Run RSync over SSH to transfer the file over to the backup server.
    # This function assumes that you have SSH access to the machine via private
    # key. It will not work otherwise.
    remote_path = join(remote_dir, basename(file_path))
    dst_str = '{0}@{1}:{2}{3}'.format(remote_user, remote_url, remote_port, remote_path)
    print('TRANSFERRING FILE:\n\tSRC: {0}\n\tDST: {1}'.format(file_path, dst_str))
    dst_str = '{0}@{1}:{2}'.format(remote_user, remote_url, remote_path)
    cmd = ['rsync', '--progress', '-Parvzy', file_path, '-e', 'ssh -p {0}'.remote_port, dst_str]
    process = Popen(cmd, stdout=STDOUT, stdin=PIPE, stderr=STDOUT)
    rsync_stdout = process.communicate()[0]


def process_encrypt_directory(dir_path, remote_user, remote_url, remote_port,
                              remote_dir, passphrase, delete=True, temp_dir=None):
    temp_dir = temp_dir if temp_dir else '/tmp'
    for f in listdir(dir_path):
        if isfile(f):
            src_path = join(dir_path, f)
            r_filename = random_filename()
            encrypted_dst_path = join(temp_dir, r_filename)
            encrypt_file(src_path, encrypted_dst_path, passphrase)
            yield (src_path, r_filename)
            transfer_encrypted_file(encrypted_dst_path, remote_user, remote_url, remote_port, remote_dir)
            if delete: remove(encrypted_dst_path)
        elif isdir(f):
            child_dir = join(dir_path, f)
            for src_path, r_filename in process_encrypt(child_path, remote_user, remote_url, remote_port, remote_dir, passphrase, delete, temp_dir):
                yield (src_path, r_filename)

def main():
    # Parse the arguments and run the appropriate functions
    
    # Prompt the user for a password
    # The author of this software strongly discourages modifying this program
    # to take a password as a commandline parameter.
    pswd = getpass.getpass('Password: ')
    

if __name__ == "__main__":
    main()
