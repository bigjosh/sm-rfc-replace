A little program that lets me add a custom `Reply-to:` address to every email I send. This lets me know when someone gets hacked and lets me control spam. 

More info here..
https://josh.com/notes/anti-spam-system/a2-rfc.txt

# Install

I use this as a command line program under SmarterMail, but (for now) it only reads and modifies standard RFC5322 .EML files so 
should work with any email server if you can figure out how to set it up to call this on every outgoing email. 

In SmarterMail you do this under Settings->General. You turn on command line program and put something like this as the command line...

```
c:\bin\sm-replace-replyto.exe %filepath "miskabibble@diddywats.com" "Josh Doe <new-%s@mydomain.com>" 3831184516 "g:/logs/"
```   

...where...

`c:\bin\sm-replace-replyto.exe`
is the full path to the executable to the program in this repo (you can get it from releases). Must have execute privileges. 

`%filepath`
is a fixed string defined by SmarterMail that will be repalced with the filename of the EML file in the spool directory by SmarterMail on each call. 

`"test-ac339@mydomain.com"`
This is the "match" email address. It is a shared secret between you and this command line. The program will only process emails
with this in the "Reply-to:" field, so the way you show the program that an email is really from you and that it should process it
is by setting the "reply to" in your email program (Outlook, GMAIL, etc) to the same special value that you pass on the command line
here. Otherwise it is not used for anything since the point of the program is to replace this with a generated address. Note that
some email programs have restrictions on what kinds of addresses you can put in here, but it does not matter because you can put
anything here as long as it is the same in both places. 

`"Josh Doe <new-%s@mydomain.com>"`
This is a template for what the generated replyto addresses should look like. The %s is replaced with a 5 letter/number hash by this program.

`3831184516`
This is the hash seed. It is the starting value for the hash that turns each recipient's email address into the
5 character code that goes where the `%s` is in the template above. Pick any number you like and then keep it
secret and never change it -- it is what makes your generated addresses yours. Two things to know:

1. Changing the seed changes every address the program generates from then on. Old addresses you already handed
out keep working (they are just mailboxes), but a recipient you emailed before and after the change will get two
different codes, and the codes in your existing log files will no longer match what the program produces now. So
decide on a seed once, up front, and write it down somewhere safe along with your match address.

2. It must be a whole number that fits in an unsigned long, so on Windows that is `0` through `4294967295`.
Anything bigger is silently clamped to `4294967295`, which means you would end up sharing a seed with everyone
else who pasted in a too-big number. There is no benefit to a longer number, so just stay under the limit.

Note that the code is only 5 hex digits (20 bits, so about a million possibilities) no matter what seed you use,
which is why the collision warning below applies.

`"g:/logs/"`
This is an optional directory to write the logs into. Make sure it exists and has write, create, and modify rights. This is very handy
to keep track of who got what addresses (see below).

# Use

Once you are set up, anyone you send an email to will reply back to their special hash address. If you ever get a spam on one of these
addresses, you can go look up who you gave that hash to and tell them that they got hacked. 

To figure out who it was, goto the logs directory and search for the file with the name of the generated reply address (with .log at the end). Open this file and you will see a list of email address you ever sent that hash to and when. 

Note that there might might be multiple people who got the same hash in case:

1. a hash collision (very unlikely)
2. You send an email with multiple "to:" people. 

## The multiple "to" problem

Unfortunately the EML file can not tell you everything about an outbound email. For example there could be a bcc which is not in the EML
file. 

Also, in the case with multiple recipients for a single email we currently just hash on the first email address. 

Someday these problems will be solved by using the HDR file which has the actual delivery info in it, but for now this will have to suffice. I am just hesitant to do this becuase I can not find any documentation on the HDR file. 
