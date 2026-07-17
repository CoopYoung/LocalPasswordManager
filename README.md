# LocalPasswordManager
As a result of losing my password cache from Brave Browser after a GPU MMU fault, I changed my desktop environment to KDE Plasma and therefore lost my old profile. After spending too much time trying to recover my passwords, I decided to make my own password manager. This manager is fully local and is secure inside a vault which is safeguared by a custom master password. This leverages rbw, a rust created bit warden CLI, without the need for creating a local server. This is all saved on harddrive and encrypted. Thus, rbw will need to be installed. Secondly, libsodium must be installed, as that is the cryptographic library utilized. 

## Features
clipboard copying, random password generation, vault safeguarding, customized password lengths
### Installation

``` apt install rbw libsodium-dev xclip wl-clipboard ```
``` make ```

### Helpful commands

I created a symlink so this can be run inside any directory on your Linux machine.

To create the vault: ``` cbw init ``` 

`
Commands:
  init       Initialize encrypted vault (set master password)
  gen        Generate password via rbw and store encrypted
  get        Retrieve and reveal a password
  insert     Insert a new entry into the vault
  list       List all entries (labels + usernames)
  delete     Delete an entry
  help       Show this help
  version    Show version

Examples:
  cbw init
  cbw gen 5 -u HappyFeather -l feathers.com
  cbw get -c feathers.com                      # copy password to clipboard
  cbw get helloworld
  cbw list
`