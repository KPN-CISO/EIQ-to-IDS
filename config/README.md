Steps to get started:

1) [Required] Create a 'settings.py' file  
2) [Required] Make it executable: chmod 700 settings.py  
3) [Required] Edit the file and enter your EIQ settings:  
  
EIQHOST='https://myeiq.localdomain'  
EIQVERSION='/private'  
EIQFEEDS='/open-outgoing-feed-download'  
EIQUSER='yourautomationuserslogin'  
EIQPASS='yourautomationuserspassword'  
EIQSOURCE='yourautomationuserssourceuuid'  
EIQSSLVERIFY=True  
  
4) [Optional] Set EIQSSLVERIFY to False if you do not want SSL certificate verification  
5) [Required] Put the following configuration options in the file:  
  
COMMENT='Your default comment on what to do with an alert (for your SOC analysts)'  
ACTION='file'  
OUTPUTFILE='eiq_to_ids.txt'  
EMAILFROM='script@localhost.localdomain'  
EMAILTO='recipient@localhost.localdomain'  
EMAILSUBJECT='e-mail subject'
EMAILSERVER='smtp.localhost.localdomain'  