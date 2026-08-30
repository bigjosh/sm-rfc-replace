A little program that lets me add a custom `Reply-to:` address to every email I send. This lets me know when someone gets hacked and lets me control spam. 

More info here..
https://josh.com/notes/anti-spam-system/a2-rfc.txt

# Install

I use this as a command line program under SmarterMail, but (for now) it only reads and modifies standard RFC5322 .EML files so 
should work with any email server if you can figure out how to set it up to call this on every outgoing email. 

In SmarterMail you do this under Settings->General. You turn on command line program and put something like this as the command line...

```
c:\bin\sm-replace-replyto.exe %filepath "miskabibble@diddywats.com" "Josh Doe <new-%s@mydomain.com>" 53431184516 "g:/logs/"
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

`"g:/logs/"`
This is an optional directory to write the logs into. It is created for you if it is not already there, so it just needs write, create,
and modify rights on the parent. This is very handy to keep track of who got what addresses (see below).

Inside it, the per-address logs go in a subfolder named for the seed, so `g:/logs/2774565/` holds every address generated with seed
`2774565`. That keeps each identity's addresses separate and searchable, and means you can list everything one identity has ever
handed out just by listing a folder. The general `log.txt` stays at the top level, because errors can happen before the program knows
which seed applies. (The folder is named for the seed as the program parses it, so an out-of-range seed shows its clamped value —
see the warning about big seeds below.)

## Multiple addresses

You can give it as many `address` / `template` / `seed` sets as you like. Just repeat all three, in that order, as many times as you
want. Every outgoing email is checked against all of them, and the first set whose match address turns up in the `Reply-to:` decides
which template and which seed get used. So this watches for two different match addresses and sends them to two different domains:

```
c:\bin\sm-replace-replyto.exe %filepath "work@diddywats.com" "Josh Doe <w-%s@mydomain.com>" 1843177432 "home@diddywats.com" "Josh <h-%s@otherdomain.com>" 22334455 "g:/logs/"
```

Two rules:

1. Always give all three parts of a set. An address without its template and seed is an error.
2. The log directory is still optional, but if you use it, it has to be the **very last** argument, after all the sets.

Command lines that were written for the old single-address version keep working exactly as they did, so there is nothing to change
if you only have one address.

## If you get it wrong

Each set is checked before any email is touched. The match address has to have an `@` with a dot somewhere after it, the template
has to have a `%s` in it, and the seed has to be plain digits. If any set fails, the program writes the reason to `log.txt` (and to
stderr) and exits **without modifying the email at all** - better to send the mail through untouched than to rewrite it using a
setting it does not understand. So if mail suddenly stops getting reply addresses after you edit the command line, look in `log.txt`
for a line starting with `BAD CONFIG`.

Note that it always exits with status 0, even on a bad command line, because it is not documented what SmarterMail does with a
non-zero exit code from the command line hook and a held message would be worse than a missing header.

## A warning about big seeds

The seed is a 32 bit number, so the largest one that actually works is `4294967295`. Anything bigger is silently clamped down to
`4294967295` - which means the `53431184516` in the Install example at the top of this page is not really the seed being used.
That has always been true and is left alone deliberately, because changing it
now would change every reply address the program has ever generated and break the lookups in your existing log files.

It only really bites you once you have more than one address set: **any two sets with seeds above `4294967295` clamp to the same
value**, so they will generate the same reply address for the same recipient and you lose the ability to tell them apart. If you
are adding a second set, keep every seed at or below `4294967295`.

# Upgrading from a version before the hash fix

**Do this once, before you run the new build, or every one of your existing correspondents will quietly get a brand new address.**

Older versions kept the per-address logs loose in the top of the log directory. They now live in a per-seed subfolder, and that
subfolder is where the program looks to find out who already has an address. So move your existing logs into it:

```
md g:\logs\2774565
move g:\logs\*.log g:\logs\2774565\
```

...where `2774565` is your seed. (`*.log` deliberately does not match `log.txt`, which belongs at the top level.)

If you skip this, nothing breaks and no mail is lost — the program just cannot see that it has met these people before, so it
issues them fresh addresses. The old addresses keep working if your server still accepts them, but the same person ends up with
two of them.

## Why the hash changed

The old hash was badly broken. It reduced with `% 0xFFFFF`, and `0xFFFFF` is `1048575 = 3 x 5 x 5 x 11 x 31 x 41`, which is
divisible by 33 — the number the DJB2 algorithm multiplies by on every character. When the multiplier shares a factor with the
modulus the multiply stops shuffling and starts collapsing, and the result is that **`hash mod 33` was always just
`(last character of the address) mod 33`**. The seed and every other character were thrown away. Since almost every email address
ends in `m`, from `.com`, nearly everybody was crammed into one thirty-third of the available addresses.

Measured over 10,000 realistic addresses, **20.4%** of people shared an address with somebody else, where a working hash of this
size gives about **1%**. It got worse as you added contacts — over 36% at 20,000. So the note further up about collisions being
"very unlikely" was wrong, and this is the fix.

The repair is a single character, `%` becomes `&`, which makes the modulus `2^20` instead of `2^20-1`. 33 is odd so it no longer
shares a factor, and the measured collision rate drops to **0.88%** — as good as a hash this size can get.

## How your old addresses keep working

The addresses already handed out came from the broken hash and are sitting in other people's address books, so they have to keep
resolving to the same people forever. Both hashes therefore ship, and the program works out which one you are owed:

1. It computes what the **old** hash would have given this recipient, which tells it the exact name of the log file that address
   would have been recorded in.
2. If that file is there and it lists this recipient, then they already have that address, and they get it again.
3. Otherwise they are somebody new, and they get the fixed hash.

There is no index to build and nothing to keep in sync — the log directory already *is* the index, it is just filed by address, and
the address is something the program can work out for itself. The cost is one failed file open for a new correspondent and one small
read for an existing one, on the small number of emails that get processed at all.

Your existing correspondents keep their old addresses and, with them, their old collisions. Only new people benefit. So the overall
rate improves as you meet new people rather than getting steadily worse: from 20.7% to around 11.6% by the time you have added
another 10,000 contacts, against 36.2% if this were left alone.

If you run without a log directory there are no records to consult, so everybody is treated as new.

# Use

Once you are set up, anyone you send an email to will reply back to their special hash address. If you ever get a spam on one of these
addresses, you can go look up who you gave that hash to and tell them that they got hacked. 

To figure out who it was, goto the logs directory, open the subfolder for the seed you are using, and find the file with the name of
the generated reply address (with .log at the end). Open this file and you will see a list of email address you ever sent that hash
to and when. `log.txt`, at the top level, also records which address set matched each processed email and whether the recipient was
given a pre-existing address or a new one.

An email whose `Reply-to:` is not one of your match addresses is passed through with its `Reply-to:` left exactly as it was.

Note that there might might be multiple people who got the same hash in case:

1. a hash collision
2. You send an email with multiple "to:" people. 

Collisions are not as rare as you would hope. The hash is only 5 hex digits, so about **1% of contacts share an address with
somebody else by the time you have 10,000 of them**, and that rises with the square of your contact count. Addresses issued by
versions before the hash fix are much worse — see below. If you find two names in one `.log` file, this is why.

## The multiple "to" problem

Unfortunately the EML file can not tell you everything about an outbound email. For example there could be a bcc which is not in the EML
file. 

Also, in the case with multiple recipients for a single email we currently just hash on the first email address. 

Someday these problems will be solved by using the HDR file which has the actual delivery info in it, but for now this will have to suffice. I am just hesitant to do this becuase I can not find any documentation on the HDR file. 
