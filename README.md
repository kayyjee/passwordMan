# passwordMan

cmd line password manager I made for a cryptography course project

* Requires mongodb 
  Set db paramaters in line 5


Description:

Authenticates with master key.

Hashes key with md5 or SHA256. Hash key is used as salt for other passwords.

Encrypts passwords with AES.



Use:

$ python passwordMan.py
