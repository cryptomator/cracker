# Usage

1. Download [the latest release](https://github.com/cryptomator/cracker/releases/latest)
2. Generate a list of possible passwords on STDOUT
3. Locate the `masterkey.cryptomator`
4. Feed the passwords to the cracker utility: `cat passwords.txt | java -jar cracker-x.y.z-fat.jar path/to/masterkey.cryptomator`

# Tips

* If you still have access to your vault on some other device (password saved by OS), make good use of it
* I can't stress this enough: Reduce the set of possible passwords as much as you can! Try to remember the password recipe
* Bruteforcing scrypt-protected passwords is a hard job for your CPU. Keep it cool to prevent thermal throttling
* Next time: Use a password manager