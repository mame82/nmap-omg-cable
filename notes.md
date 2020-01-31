# O.MG cable defense notes

## General notes

For backend interface, O.MG cable exposes a WebSocket based API.
As the WebServer itself isn't running HTTPS, the websocket isn't
encrypted either.

The websocket endpoint for API access resides at `ws://<omg_cable_host>/d/ws/issue` and
follows the default implementation of [cnlohr's esp82xx project](https://github.com/cnlohr/esp82xx).
The WebSocket implementation of the esp82xx project has several limitations, amongst others:

- only send unmasked WS responses (no XOR, just plain data, which could easily captured)
- has no support for requests with 4 byte length encoding (less of an issue, as an
  ESP couldn't handle them anyways)

The simplified WebSocket implemtation of the nmap NSE script in this repo builds
on top of those constraints. Although masked requests are enforced by the server,
the nmap script always uses a XOR mask of `0x00 0x00 0x00 0x00`, so one could easy
follow along raw TCP captures.

## WS API calls

API uses ASCII encoded commands, arguments are separated with `\t`.

API responses contain complete request data and optional additional
response data (again separated with `\t`).

### some API calls

```
FB<addr base10>				        Flash write block
FX<addr base10>				        Flash erase block
FR<addr base10>\t<length base10>	Flash read
CN1					                Flash erase sensitive data regions
CD1					                Full erase
```

Note:

There are additional API calls which are of less interes, as arbitrary remote
flash read/erase/write is possible with the ones listed above.

Unprotected API access essentialy allows to dump,modify and reflash the firmware
remotely (not signed). Beside forensics and defensive approaches, this
allows to re-place the firmware with a modified version, which itself "attacks"
other accessible O.MG cables. Replacing pure user_data (payloads, WiFi settings etc.
is possible, too.

In summary the device is only protected by WiFi encryption. If it is placed in
a WiFi network owned by blueteam, it is easy to spot and defeat. This could be fully
automated.

Beside low level flash based options to defeat the cable, there are other interesting
approaches to isolate it from the attackers access.

An example is the possibility to use the WS API to change the WiFi settings in
order to let the cable work as STA (WiFi client mode) with invalid SSID/PSK.
Ultimately, the cable tries to connect to the invalid WiFi repeatedly (which
maybe involves sending probe request frames, haven't hecked this).
In result **the attacker loses access to the cable, while the blueteam is able
conventianal tools to track down the physical position of the cable for further
inverstigations** (either by following probe request frames or, in case of their
absence, by opening up the desired configured WiFi and following RSSI once the
cable connects)

# Flash addresses of interest

```
0x7f800			boot payload enabled
0x7f810			pay slot boot
0xa9000			pay slot 1
0xaa000			pay slot 2
0xab000			pay slot 3
0xb0000			external IP
0xfd000/0xfe000		current config
```
