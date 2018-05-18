# Steps to get started

1) Create a settings.py file
2) Put all entries listed below in them
3) Replace values to match your environment

```
COMMENT='KPN-CERT'
```

4) Default action and output file

```
ACTION='file' # file, mail, ...  
OUTPUTFILE='eiq_to_ids.txt'
```

5) E-mail settings

```
EMAILFROM='sender_address@goes.here'  
EMAILTO='recipient_address@goes.here'
EMAILSUBJECT='EIQ-to-IDS output'
EMAILSERVER='your_smtp_server'
```

6) EclecticIQ settings

```
EIQHOST='https://eiq.your.lan'
EIQVERSION='/private'
EIQFEEDS='/open-outgoing-feed-download'
EIQUSER='automationuser'
EIQPASS='automationuserpass'
EIQSOURCE='automationusersourceuuid'
EIQSSLVERIFY=False
```

7) Snort / SourceFire rule settings

This is used to map EIQ observables to specific SIDs. If you delete this file, or it doesn't exist, a completely new ruleset will be generated at the start SID value, otherwise older rules for newer variables will be overwritten with a newer revision for the same SID.

```
SID=7000000
GID=1
PRIORITY=1
CLASSTYPE='your_classtype_here'
SIDFILE='snort.sdb'
```

8) HTTP settings

If you have an HTTP proxy, change the HTTP_PROXYSERVER and -PORT setting from 'None' to its IP. The HTTP_PROXYPORTS setting will then be used to generate rules matching HTTP traffic to the specified proxyserver.

```
HTTP_PROXYSERVER=None
HTTP_PROXYSERVERPORT=8080
HTTP_PORTS='[80,443,3128,8000,8008,8080,8443]'
IMAP_PORTS='[143,993]'
POP3_PORTS='[110,995]'
SMTP_PORTS='[25,465,587]'
```
