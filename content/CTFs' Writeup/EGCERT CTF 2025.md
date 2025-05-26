---
title: EGCERT CTF 2025
tags:
  - ctf 
draft: false
---
![[Pasted image 20250526071321.png]]
Hello everyone and welcome to my blog! 
In this write up we'll be solving the `Phantime` reverse engineering challenge from the EGCERT Qualifications CTF of 2025! (Obtained <mark style="background: #FF5582A6;">First Blood</mark>)

# Phantime Challenge

## Basic Triage
The challenge initially had no description and were given an executable `phantime.exe`.
Upon execution, we're asked for a 4 character code:
![[Pasted image 20250526052623.png]]
Now initially, I had thought about brute forcing the code but it seems to be taking small intervals in between checks.
![[Pasted image 20250526052849.png]]
Checking the program's strings, we some interesting references to **registry keys** and a string format that points to the "flag".
![[Pasted image 20250526053351.png]]
Given this information initially, we know that the executable stores the flag in some registry keys in the format `flag{ghost_in_your_hive_%s}`, all what's missing now is to find the 4 character code, setup `procmon64.exe` and configure the filters to the executable and check for any registry changes.
>[!note]
 You could use `regshot`, but if these changes were dormant: the next iterations of the execution might not capture any new registry changes because the 1st shot would contain the newly created registry keys.
 
We can also confirm that the executable uses registry-related functions by looking at the IAT.
![[Pasted image 20250526054629.png]]
## Disassembly
Taking a look at the disassembly, we can see that the printing functions that we've seen when we execute the binary and compares our input with `v7`.![[Pasted image 20250526062433.png]]
Going inside the function that sets up `v7`, we can find that it sets it up to `'TIME'`
![[Pasted image 20250526062534.png]]
>[!note] Oops, my bad
> When I first had solved this, I didn't bother checking for the v7 variable and instead vibecoded a script that bruteforces the character code, but it takes a few minutes since the executable uses sleep functions to delay it.
>```python
>import subprocess
>import string
>import time # Character set: adjust if needed
>charset = string.ascii_letters + string.digits
>code = ['A', 'A', 'A', 'A']
>for pos in range(4):
>    max_time = 0
>    best_char = ''
>    print(f"[*] Brute-forcing position {pos+1}...")
>    for c in charset:
>        attempt = code.copy()
>        attempt[pos] = c
>        start = time.time()
>        try:
>            proc = subprocess.Popen(
>                ['phantime.exe'],
>                stdin=subprocess.PIPE,
>                stdout=subprocess.PIPE,
>                stderr=subprocess.PIPE,
>                creationflags=subprocess.CREATE_NO_WINDOW  # Hide the window
>            )
>            # Send the code and flush
>            proc.stdin.write((''.join(attempt) + '\n').encode())
>            proc.stdin.flush()
>            # Wait for the process to finish (timeout to avoid hangs)
>            proc.communicate(timeout=5)
>        except subprocess.TimeoutExpired:
>            proc.kill()
>        elapsed = time.time() - start
>        print(f"Trying {''.join(attempt)}: {elapsed:.2f}s")
>        if elapsed > max_time:
>            max_time = elapsed
>            best_char = c
>    code[pos] = best_char
>    print(f"[+] Found character {pos+1}: {best_char}")
>    print("[*] Code is:", ''.join(code))

Now that the key has been obtained, we can setup procmon64 and capture any registry related events.

These are the filters that I've used to capture the events.
![[Pasted image 20250526064405.png]]
And when we execute the binary and enter the code, we get 4 events. We're interested only in the `RegSetValue` operation, and it seems that we hit the jackpot!
![[Pasted image 20250526064517.png]]
..except that this is not the flag, this is only a fake flag put to deceive the player.

So our initial plan has failed, we'll have to dig deep inside the binary and see what the binary does in detail.

## Plan B
Since we know that our password triggers a path, we'll have to analyze that path and see what the binary does.
![[Pasted image 20250526064827.png]]
The first function isn't really important, as it only obtains a handle to a registry key.
The second function, however, is where all the fun resides.
### Main_Event()
The first few functions basically sets up a character generator, and really that important to the solution.
Then we see that it starts to setup what appears to be hardcoded encoded data and starts to XOR it with `MEOWMEOW`.
![[Pasted image 20250526065716.png]]Then it takes that encoded flag and passes it to the `CollectionData` key.
![[Pasted image 20250526070328.png]]
Then we know that this encoded string exists in the registry of type `REG_BINARY`.
![[Pasted image 20250526070528.png]]
### Finale
We can go ahead and go inside the registry and obtain this data and XOR it with `MEOWMEOW` to obtain the _real_ flag.
![[Pasted image 20250526071125.png]]
Flag: `EGCTF{password_timing_attack_0mlbTG}`

This has been my 3rd time participating in a CTF so it has been loads of fun, thanks for reading and I'll see you on the next one! GGWP!