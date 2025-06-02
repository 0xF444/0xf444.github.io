---
tags:
  - "#CTF"
  - "#Reverse-Engineering"
---

Hello everyone and welcome to my writeup for the [N0PSctf](https://ctf.nops.re/) CTF!
![[Pasted image 20250602100712.png]]
In this writeup we'll be solving the `Invaders` challenge from PwnTopia (Reverse Engineering)

This challenge was indeed one of the most fun ones I've had in a while and with a little gist at the end, so stick around for that. :) (Thanks @CaptWake)
![[Pasted image 20250602121306.png]]
# Initial Triage
We're presented with a whopping `80.3 MB` file that has an interesting description: `Godot Engine` and has the icon of that engine.
![[Pasted image 20250602121835.png]]
Needless to say, this file is impossible to statically analyze using normal PE analysis tools such as IDA.

Opening the file; we're presented with a mimic of space invaders that is completely playable, use the arrow keys to move and space bar to shoot.
![[Pasted image 20250602122224.png]]With this being said, we need to have a little bit of [insight](https://docs.godotengine.org/en/stable/tutorials/scripting/index.html) about the engine if we are to reverse engineer it.
![[Pasted image 20250602122439.png]]
The Godot Engine allows you to code games in 3 programming languages: C#, GDScript or GDExtension, whomever they are; we need to find a way to extract them from the original executable. We can google any tools related to reverse engineering Godot Engine based executable, and indeed we find one tool: [GDRETools for GDScript Decompilation](https://github.com/GDRETools/gdsdecomp)
Putting our large executable in the tool, we can extract the GDScript script files `(.gd)` and analyze them.
![[Pasted image 20250602124358.png]]
After checking the extracted project file, we see an interesting `game.gd` file that contains the "script" for the game. ![[Pasted image 20250602124621.png]]
We can see that the script does some stuff related to the game itself, and it sets up a byte array `f` and XORs it with the byte array of `e` for each element and then reiterates the XOR byte array after 4 steps (The use of the `%` operator)

Nevertheless, we can extract the byte arrays and do them in a Python script, write the output in a file and see what we get...

```python
f = bytes([]) # Insert full key here, it's too big for obsidian to handle lol
e = bytes([74, 111, 74, 111])
v = bytearray()
for w in range(len(f)):
    v.append(f[w] ^ e[w % len(e)])
with open("output.bin", "wb") as out_file:
    out_file.write(v)
```
# The Second Stage
So we have our output in `output.bin`, using the `file` tool: we can see that it's actually a PE file!
![[Pasted image 20250602125626.png]]
Upon execution, we're greeted with some very cool ASCII art and then the program asks us to save Espeax from the evil cryptic binary!
![[Pasted image 20250602125748.png]]
The program does not receive any input, although it says that the right key must be found **hidden somewhere in the environment.**

>[!note] Spoiler Alert
> The fact that the binary mentioned an "environment" could mean the environment variables of the application, more on that in a bit.

## Basic Static Analysis
Using DiE, we are able to conclude that the executable is a C++ program, so we'll see lots of name mangled functions.
![[Pasted image 20250602140009.png]]
Checking the PE file for imports we see entries of Cryptography related functions from `ADVAPI32.DLL` such as `CryptCreateHash`, `CryptHashData`, etc...
We also see imports of `CreateThread` and `CreateEvent` from `kernel32.dll` which generally can be used by the CRT but as we will see later, we'll see that they're used in the main function's logic.
![[Pasted image 20250602140236.png]]
Strings do not provide anything useful, except for the cool ASCII art used by the program.
With that said, we advance to the disassembly!
## Disassembly of the PE file
Checking the psuedocode of the PE file, we land at the `main` function directly:
we see the `cout` function used to print out the ASCII art which is not really interesting. Then it sets up 2 event objects, these objects will be important later on.
![[Pasted image 20250602141127.png]]
Then we create two threads objects that take [[#StartAddress()]] and [[#sub_140001290()]] respectively, lastly the main function will wait for both event objects to be set if we are to proceed execution of the main function, so our goal here is to analyze `StartAddress` and `sub_140001290`.
### StartAddress()
This function first takes the address of some data address and then begins to iterate over it such that it increases each data index with the value of it's index `arr[i]+=i;`
![[Pasted image 20250602142018.png]]
We can do this operation manually using a simple Python script (vibecoded really):
```python
pbData = [
    0x59, 0x2F, 0x73, 0x5C, 0x44,
    0x2F, 0x70, 0x2C, 0x57, 0xF7
]
for count in range(10):
    pbData[count] = (pbData[count] + count) & 0xFF  
print("Modified pbData:")
print(" ".join(f"{byte:02X}" for byte in pbData))
```
It prints out `59 30 75 5F 48 34 76 33 5F 00` which corresponds to `Y0u_H4v3_` and a null terminator.
![[Pasted image 20250602142350.png]]
The remainder of this function basically takes the bytes after the forementioned loop and takes the SHA256 hash of it and then compares it to a hardcoded hash (which turns out to be itself) and if it's equal: then we set the first event object.
![[Pasted image 20250602142557.png]]
Putting the data into a [SHA256 Hash tool online](https://emn178.github.io/online-tools/sha256.html), we can see that the data's hash is exactly the same as the hardcoded one, so we don't need to do anything for [[#StartAddress()]].
![[Pasted image 20250602143516.png]]
So that's the first event object set!
### sub_140001290()
As for the second function, we see what looks like a base64 encoded string then it goes to do some decoding (most likely base64 decoding)
![[Pasted image 20250602144410.png]]
So checking that base64 encoded string:
![[Pasted image 20250602151524.png]]
This evaluates to `GetEnvironmentVariableA`, so we have an idea that it attempts to resolve this API call at runtime (which is why we couldn't see this function in the IAT)
It proceeds to decode this base64 string (which is not really important to our analysis)
Then it attempts to load up `kernel32.dll` and more importantly retrieves the address of `GetEnvironmentVariableA()`
![[Pasted image 20250602153941.png]]
Then it calls [`GetEnvironmentVariableA()`](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) to check for the `N0PS_ENV` environment variable, since the function does operations on some data, we can simply run this in a debugger and see how it evaluates the data that it compares to.

>[!warning] Before you debug:
>The program needs to have a `N0PS_ENV` environment variable given to it using the `set` command in a command prompt that will run the program (even if it doesn't have a value) otherwise the initial `if` statement will fail and the program will return and exit, unless you can patch the instructions responsible for the environment variable check (Program was loaded at `IMAGE_BASE` of `0x140000000`): 
>![[Pasted image 20250602160258.png]]
#### Debugging Session
With that said, we can patch the executable so that it can work without checking for that environment variable and see what it waits for: 
![[Pasted image 20250602162207.png]]
So we've concluded that this function awaits an environment called `N0PS_ENV` that needs to have the value of `S4V3D_3SPE4X` and that should set the second event and the rest of the `main` function can proceed.
# Flag Time
So we basically need to set up a command prompt with an environment variable called `N0PS_ENV` with the value `S4V3D_3SPE4X` using the `set` command: `set N0PS_ENV=S4V3D_3SPE4X` then we execute our program in that command prompt:
![[Pasted image 20250602162807.png]]
And we obtain our flag!!!
> `N0PS{Y0u_H4v3_S4V3D_3SPE4X}`
# Final Remarks
This challenge was loads of fun, this was my first time participating in N0PSctf so being able to solve a challenge was really really great!
One problem though, when I first decompiled the GDScript file it gave me an executable but it was about saving *Jojo* instead, not _Espeax_: ![[Pasted image 20250602163054.png]]
This one is solvable using the steps we've shown in the writeup but it will give you a false flag `N0PS{Y0u_H4v3_S4V3D_J0JO}`. I don't really know how that happened exactly but I've assumed it's a problem with my attempt to decompile the `game.gd` GDScript file.
So basically I've saved two people for the price of one flag..

Regardless, the challenge was loads of fun either way.

Thanks for reading till the end and see you on the next one! GGWP!

[^1]: 
