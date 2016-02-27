#!/usr/bin/python3

from argparse import ArgumentParser
from getpass import getpass
from subprocess import check_output, Popen, PIPE, STDOUT
from os import listdir, remove, getcwd
from os.path import join, basename, isfile, isdir, abspath
from socket import socket, AF_INET, SOCK_STREAM
from re import compile
from datetime import datetime


def ssh_available(url, port=22):
    s = socket(AF_INET, SOCK_STREAM)
    available = None
    try:
        s.connect((url, port))
        available = True
    except error as e:
        available = False
    finally:
        s.close()
    return available


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
    process.stdin.close()


def decrypt_file(src_file_path, dst_file_path, passphrase):
    # Run the GPG command to decrypt a symmetrically encrypted file and write the results to a destination
    print('DECRYPTING FILE:\n\tSRC: {0}\n\tDST:{1}'.format(src_file_path, dst_file_path))
    cmd = ['gpg', '--yes', '--passphrase-fd', '0', '--output', dst_file_path, '--decrypt', src_file_path]
    process = Popen(cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE)
    gpg_stdout = process.communicate(input=passphrase)[0]
    process.stdin.close()


def transfer_encrypted_file(file_path, remote_user, remote_url, remote_port,
                            dst_dir):
    # Run RSync over SSH to transfer the file over to the backup server.
    # This function assumes that you have SSH access to the machine via private
    # key. It will not work otherwise.
    dst_file_path = join(dst_dir, basename(file_path))
    dst_str = dst_file_path
    dst_str = remote_url + ':' + dst_str if remote_url else dst_str
    dst_str = remote_user + '@' + dst_str if remote_user else dst_str
    print('TRANSFERRING FILE:\n\tSRC: {0}\n\tDST: {1}'.format(file_path, dst_str))
    cmd = ['rsync', '--progress', '-Parvzy', file_path, '-e',
           'ssh -p {0}'.format(remote_port), dst_str]
    print(cmd)
    process = Popen(cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE)
    rsync_stdout = process.communicate()[0]
    print(rsync_stdout)
    process.stdin.close()


def process_encrypt_directory(dir_path, remote_user, remote_url, remote_port,
                              remote_dir, passphrase, delete=True,
                              temp_dir=None):
    temp_dir = temp_dir if temp_dir else '/tmp'
    for f in listdir(dir_path):
        if isfile(f):
            src_path = join(dir_path, f)
            r_filename = random_filename()
            encrypted_dst_path = join(temp_dir, r_filename)
            encrypt_file(src_path, encrypted_dst_path, passphrase)
            yield (src_path, r_filename)
            transfer_encrypted_file(encrypted_dst_path, remote_user, remote_url,
                                    remote_port, remote_dir)
            if delete:
                print('DELETING: {0}'.format(encrypted_dst_path))
                remove(encrypted_dst_path)
        elif isdir(f):
            child_dir = join(dir_path, f)
            for src_path, r_filename in process_encrypt_directory(child_dir,
                                                                  remote_user,
                                                                  remote_url,
                                                                  remote_port,
                                                                  remote_dir,
                                                                  passphrase,
                                                                  delete,
                                                                  temp_dir):
                yield (src_path, r_filename)


def main():
    # Parse the arguments and run the appropriate functions
    parser = ArgumentParser()
    parser.add_argument('source_dir', metavar='SOURCE-DIRECTORY', type=str,
                        help='The source directory that is to be backed up.')
    parser.add_argument('destination', metavar='DESTINATION', type=str,
                        help='The destination (remote) directory where the '
                             'backup will be placed.')
    parser.add_argument('--no-delete', action='store_true',
                        help='Do not delete local temporary encrypted files.')
    parser.add_argument('-t', '--temp-dir', type=str,
                        help='Specify the temp directory for encrypted files.')
    parser.add_argument('-l', '--logfile', type=str,
                        help='Specify a logfile to be used to record files and '
                             'their randomized names')

    # Parse the arguments
    arguments = parser.parse_args()
    if isdir(arguments.source_dir):
        url_pattern = compile(r'(.*\@)?(.+):(\d*)(\/.*)')
        url_match = url_pattern.match(arguments.destination)
        if url_match:
            print(url_match.groups())
            remote_user = url_match.group(1) if url_match.group(1) else None
            remote_url = url_match.group(2)
            remote_port = url_match.group(3) if url_match.group(3) else 22
            dst_dir = url_match.group(4)
            if not ssh_available(remote_url, remote_port):
                print("Connection unavailable!")
                parser.print_help()
                exit()
        elif isdir(arguments.destination):
            remote_user = None
            remote_url = None
            remote_port = None
            dst_dir = arguments.destination
        else:
            print("Invalid destination")
            parser.print_help()
            exit()
        temp_dir = arguments.temp_dir
        delete = not arguments.no_delete

        # Create a logfile:
        if arguments.logfile:
            logfile = arguments.logfile
        else:
            time_str = str(datetime.now()).replace(' ','_')
            logfile = join(getcwd(), '{0}_gpg-backup.log'.format(time_str))

        with open(logfile,'a+') as log:
            # Prompt the user for a password
            # The author of this software strongly discourages modifying this program
            # to take a password as a commandline parameter.
            passphrase = bytes(getpass('Password: '), 'utf-8')

            # Execute recursive call to backup the directory
            for entry in process_encrypt_directory(arguments.source_dir,
                                      remote_user, remote_url, remote_port, dst_dir,
                                      passphrase, delete, temp_dir):
                log.write(('{0} {1}\n'.format(entry[1], abspath(entry[0]))))
    else:
        print("Invalid source directory")
        parser.print_help()
        exit()

if __name__ == "__main__":
    main()
