# SecureStore

Purpose of developing this program:
- To implement a Secure Store program that provides a built-in discretionary access control mechanism.
- To protect the Secure Store program’s data-in-rest with symmetric encryption.
- To authenticate the users of Secure Store program.

Basic Usage:
 The application should have a command that shows all actions supported by Secure Store. E.g., if “help” command is provided, it should show all other commands with a brief explanation of them.
 The data stored in secure_store.dat must be encrypted in all times. The application should not store any information (e.g., meta-data, application specific data, stored files, passwords etc.) in plaintext. 
 Secure store must authenticate all its users via a username and password. When the application is run, it should be asking username and password from the user. If the provided username and password matches with one of the username-password pair in Secure store, authentication succeeds. Otherwise, authentication fails and Secure store ends working.

 Help
whoami: shows the current user who is using current program.
put [path_on_OS] [file_name]: puts the file at path_on_OS into the system with the given name file_name.
delete [file_name]: deletes the file which is in system and whose name is file_name.
get [String file_name]: writes out the file whose name is file_name and stored in our system to the current folder where program is        executed.
chown [file_name] [subject]: changes the owner of file to the subject.
grant_r [file_name] [subject]: grants read permission to the subject.
revoke_r [file_name] [subject]: revokes read permission from the subject.
grant_w [file_name] [subject]: grants write permission to the subject.
revoke_w [file_name] [subject]: revokes write permission from the subject.
ls: shows all files and their permissions accesible by current user.
ls_all: shows all files and their permissions even the current user does not have read or write permission.
reorganize: reorganizes the main storage file by deleting the files from the storage that are deleted before.
bye: exists the program.

