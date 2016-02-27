# gpg-backup
A simple python script that automates the process of encrypting a file tree and sending it over to a backup server (or local destination) using RSync.

The way that this script works is fairly simple, it recursively scans through a directory and creates an encrypted copy of each file that it finds using GPG symmetric encryption with a key/password that the user has to enter. Each encrypted file is then transferred to a local or remote destination using rsync. File names are not preserved during the backup process on purpose. Instead a log file is generated that maintains a mapping that lists the new random file name as well as the absolute path of the original.

## Requirements

This script uses Python3 and assumes a Linux/UNIX system with GPG, rsync, and SSH installed. A gpg key need not be generated. The script also assumes that if you are backing up to an encrypted server that you have your public SSH key uploaded to said server.

## Running an Encrypted Backup:

Please make sure to run `gpg-backup.py --help` to get the most up-to-date instructions on how the command-line parameters work.

### Simple example:

```
$ gpg-backup.py ./ /backups
```

This command will scan the current directory, encrypt each file and save it to the `/backups` directory. It will also generate a log file in the current directory of the form: `<Date_Time>_gpg-backup.log`.

### Remote Server Examples:

```
$ gpg-backup.py /my/personal/files abraxos@myserver.com:/my/backups
$ gpg-backup.py /my/personal/files abraxos@myserver.com:222/my/backups
$ gpg-backup.py /my/personal/files myserver.com:/my/backups
```

All of the above are valid ways to run the script to backup files to a remote server. Note that a non-standard port may be used, but the default port will always be 22. Similarly when no username is specified RSync/SSH will attempt to use the current username.

### Other Stuff:

You can specify the logfile:

```
$ gpg-backup.py -l my_logfile.log ./ /backups
```

You can ask the script not to delete the local copies of the encrypted files:

```
$ gpg-backup.py --no-delete ./ /backups
```

And you can specify the temporary directory to be used for the encrypted files (typically recommended when using the `--no-delete` command).

```
$ gpg-backup.py --no-delete -t /my/temp/directory/ ./ /backups
```
