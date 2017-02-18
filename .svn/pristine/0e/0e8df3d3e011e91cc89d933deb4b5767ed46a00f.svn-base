/*This Sql script to label attack is produced with reference to two files,
1.	http://www.ll.mit.edu/mission/communications/cyber/CSTcorpora/files/master-listfile-condensed.txt
and
2. http://www.ll.mit.edu/mission/communications/cyber/CSTcorpora/files/master_identifications.list

*/
--First, Making every category normal
Update TCP_51_in SET category =0;
Update TCP_52_in SET category =0;
Update TCP_53_in SET category =0;
Update TCP_54_in SET category =0;
Update TCP_55_in SET category =0;
Update TCP_51_out SET category =0;
Update TCP_52_out SET category =0;
Update TCP_53_out SET category =0;
Update TCP_54_out SET category =0;

--Secondly, Labeling the  attack category by updating it with 1.
UPDATE TCP_51_in SET category =1 where srcIP = '202.77.162.213' and destIP='172.16.112.50' and packetime between '1999-04-05 08:39:52' and '1999-04-05 08:40:02' -- i
UPDATE TCP_51_in SET category =1 where srcIP = '172.16.118.10' and destIP='192.168.1.1' and packetime between '1999-04-05 08:43:17' and '1999-04-05 08:43:18' and destPort in (79,80,143)
UPDATE TCP_51_in SET category =1 where srcIP = '172.16.118.10' and destIP='192.168.1.1' and packetime between '1999-04-05 08:45:13' and '1999-04-05 08:45:14' and destPort in (79,80,143)
UPDATE TCP_51_in SET category =1 where srcIP = '172.16.118.10' and destIP='192.168.1.1' and packetime between '1999-04-05 08:47:09' and '1999-04-05 08:47:10' and destPort in (79,80,143)
UPDATE TCP_51_in SET category =1 where srcIP = '202.77.162.213' and destIP='172.16.114.50' and packetime between '1999-04-05 08:48:33' and '1999-04-05 08:48:38' --i
UPDATE TCP_51_in SET category =1 where srcIP = '207.75.239.115' and destIP='172.16.112.50' and packetime between '1999-04-05 08:59:16' and '1999-04-05 08:59:57' and destPort in (20,21)
UPDATE TCP_51_in SET category =1 where destIP='172.16.112.50' and packetime between '1999-04-05 09:33:00' and '1999-04-05 09:35:00' --i
UPDATE TCP_51_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:43:11' and '1999-04-05 09:43:19' and destPort < 101
UPDATE TCP_51_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:43:24' and '1999-04-05 09:43:25' and destPort < 101
UPDATE TCP_51_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:43:31' and '1999-04-05 09:43:34' and destPort < 101
UPDATE TCP_51_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:43:35' and '1999-04-05 09:43:38' and destPort < 101
UPDATE TCP_51_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:43:43' and '1999-04-05 09:43:44' and destPort < 101
UPDATE TCP_51_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:43:50' and '1999-04-05 09:43:52' and destPort < 101
UPDATE TCP_51_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:43:57' and '1999-04-05 09:43:58' and destPort < 101
UPDATE TCP_51_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:44:04' and '1999-04-05 09:44:08' and destPort < 101
UPDATE TCP_51_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:44:09' and '1999-04-05 09:44:13' and destPort < 101
UPDATE TCP_51_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:44:18' and '1999-04-05 09:44:19' and destPort < 101
UPDATE TCP_51_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:44:25' and '1999-04-05 09:44:29' and destPort < 101
UPDATE TCP_51_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:44:34' and '1999-04-05 09:44:35' and destPort < 101
UPDATE TCP_51_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:44:41' and '1999-04-05 09:44:43' and destPort < 101
UPDATE TCP_51_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:44:44' and '1999-04-05 09:44:49' and destPort < 101
UPDATE TCP_51_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:44:54' and '1999-04-05 09:44:55' and destPort < 101
UPDATE TCP_51_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:45:01' and '1999-04-05 09:45:04' and destPort < 101
UPDATE TCP_51_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:45:05' and '1999-04-05 09:45:07' and destPort < 101
UPDATE TCP_51_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:45:12' and '1999-04-05 09:45:13' and destPort < 101
UPDATE TCP_51_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:45:19' and '1999-04-05 09:45:28' and destPort < 101
UPDATE TCP_51_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:45:29' and '1999-04-05 09:45:39' and destPort < 101
UPDATE TCP_51_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:45:44' and '1999-04-05 09:45:45' and destPort < 101
UPDATE TCP_51_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:45:52' and '1999-04-05 09:46:02' and destPort < 101
UPDATE TCP_51_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:46:03' and '1999-04-05 09:46:14' and destPort < 101
UPDATE TCP_51_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:46:15' and '1999-04-05 09:46:21' and destPort < 101
UPDATE TCP_51_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:46:26' and '1999-04-05 09:46:27' and destPort < 101
UPDATE TCP_51_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:46:33' and '1999-04-05 09:46:34' and destPort < 101
UPDATE TCP_51_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:46:35' and '1999-04-05 09:46:36' and destPort < 101
UPDATE TCP_51_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:46:37' and '1999-04-05 09:46:48' and destPort < 101
UPDATE TCP_51_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:46:53' and '1999-04-05 09:46:54' and destPort < 101
UPDATE TCP_51_in SET category =1 where srcIP = '202.77.162.213' and destIP='172.16.114.50' and sourcePort='1389' and destPort='80' and packetime between '1999-04-05 10:29:22' and '1999-04-05 10:46:59' 
UPDATE TCP_51_in SET category =1 where srcIP = '192.5.41.239' and destIP='172.16.118.80' and sourcePort='37' and destPort='23' and packetime between '1999-04-05 10:58:14' and '1999-04-05 11:00:00'
UPDATE TCP_51_in SET category =1 where srcIP = '192.5.41.239' and destIP='172.16.118.80' and packetime between '1999-04-05 11:00:01' and '1999-04-05 11:01:34' 
UPDATE TCP_51_in SET category =1 where srcIP = '172.16.115.234' and destIP='172.16.112.100' and destPort='139' and packetime between '1999-04-05 11:45:27' and '1999-04-05 12:02:00'
UPDATE TCP_51_in SET category =1 where srcIP = '172.16.114.207' and destIP='172.16.113.50' and destPort='23' and packetime between '1999-04-05 12:03:14' and '1999-04-05 12:14:29'
UPDATE TCP_51_in SET category =1 where srcIP = '135.13.216.191' and destIP='172.16.112.50' and destPort='23' and packetime between '1999-04-05 12:11:18' and '1999-04-05 12:23:46'
UPDATE TCP_51_in SET category =1 where srcIP = '23.234.78.52' and destIP='172.16.114.50' --i
UPDATE TCP_51_in SET category =1 where srcIP = '152.169.215.104' and destIP='172.16.112.100' and packetime between '1999-04-05 13:30:14' and '1999-04-05 13:30:31'
UPDATE TCP_51_in SET category =1 where srcIP = '152.169.215.104' and destIP='172.16.112.100' and packetime between '1999-04-05 13:33:52' and '1999-04-05 13:44:51'
UPDATE TCP_51_in SET category =1 where srcIP = '152.169.215.104' and sourcePort in(2275,2276,2277,2358,2639,2750,2759,2943,3380,3483,3662,3906) and destIP='172.16.114.50' and packetime between '1999-04-05 14:05:43' and '1999-04-05 14:15:47' and destPort in (80)
UPDATE TCP_51_in SET category =1 where srcIP = '152.169.215.104' and destIP='206.48.44.50' and packetime between '1999-04-05 14:16:51' and '1999-04-05 14:16:52' and sourcePort in(2275,2276,2277,2358,2639,2750,2759,2943,3380,3483,3662,3906) 
UPDATE TCP_51_in SET category =1 where srcIP = '10.11.22.33' and destIP='172.16.113.50' and packetime between '1999-04-05 14:22:30' and '1999-04-05 14:22:31' --i
UPDATE TCP_51_in SET category =1 where srcIP = '172.16.117.103' and destIP='172.16.114.50' and packetime between '1999-04-05 14:46:19' and '1999-04-05 14:46:29' and destPort in (143)
UPDATE TCP_51_in SET category =1 where srcIP in( '128.223.199.68','172.16.113.50','204.71.51.16','204.233.47.21','207.114.237.57','209.1.12.46') and destIP='172.16.113.1' and packetime between '1999-04-05 15:00:16' and '1999-04-05 15:00:17' --i
UPDATE TCP_51_in SET category =1 where srcIP in( '128.223.199.68','172.16.113.50','204.71.51.16','204.233.47.21','207.114.237.57','209.1.12.46') and destIP='172.16.113.3' and packetime between '1999-04-05 15:04:06' and '1999-04-05 15:04:07' --i
UPDATE TCP_51_in SET category =1 where srcIP in( '128.223.199.68','172.16.113.50','204.71.51.16','204.233.47.21','207.114.237.57','209.1.12.46') and destIP='172.16.113.5' and packetime between '1999-04-05 15:07:56' and '1999-04-05 15:07:57' --i
UPDATE TCP_51_in SET category =1 where srcIP in( '128.223.199.68','172.16.113.50','204.71.51.16','204.233.47.21','207.114.237.57','209.1.12.46') and destIP='172.16.113.4' and packetime between '1999-04-05 15:11:46' and '1999-04-05 15:11:47' --i
UPDATE TCP_51_in SET category =1 where srcIP in( '128.223.199.68','172.16.113.50','204.71.51.16','204.233.47.21','207.114.237.57','209.1.12.46') and destIP='172.16.113.50' and packetime between '1999-04-05 15:15:36' and '1999-04-05 15:15:37' --i
UPDATE TCP_51_in SET category =1 where srcIP in( '128.223.199.68','172.16.113.50','204.71.51.16','204.233.47.21','207.114.237.57','209.1.12.46') and destIP='204.233.47.21' and packetime between '1999-04-05 15:15:36' and '1999-04-05 15:15:37' --i
UPDATE TCP_51_in SET category =1 where srcIP = '172.16.118.10' and destIP='172.16.114.50' and packetime between '1999-04-05 16:32:17' and '1999-04-05 16:32:27' and destPort in (23)
UPDATE TCP_51_in SET category =1 where srcIP = '172.16.118.10' and destIP='172.16.114.50' and packetime between '1999-04-05 16:32:28' and '1999-04-05 16:32:59' and destPort in (23)
UPDATE TCP_51_in SET category =1 where srcIP = '172.16.118.10' and destIP='172.16.114.50' and packetime between '1999-04-05 16:33:00' and '1999-04-05 16:33:22' and destPort in (23)
UPDATE TCP_51_in SET category =1 where srcIP = '172.16.118.10' and destIP='172.16.114.50' and packetime between '1999-04-05 16:33:23' and '1999-04-05 16:42:03' and destPort in (23)
UPDATE TCP_51_in SET category =1 where srcIP = '172.16.118.10' and destIP='172.16.114.50' and packetime between '1999-04-05 16:42:04' and '1999-04-05 16:46:09' and destPort in (23)
UPDATE TCP_51_in SET category =1 where srcIP = '172.16.118.10' and destIP='172.16.114.50' and packetime between '1999-04-05 16:46:10' and '1999-04-05 16:48:52' and destPort in (23)
UPDATE TCP_51_in SET category =1 where srcIP = '172.5.3.5' and destIP='172.16.112.50' and packetime between '1999-04-05 17:19:10' and '1999-04-05 17:34:11' and destPort in (514)
UPDATE TCP_51_in SET category =1 where srcIP = '10.20.30.40' and destIP='172.16.112.50' and packetime between '1999-04-05 18:04:04' and '1999-04-05 18:10:55' and destPort < 1025
UPDATE TCP_51_in SET category =1 where srcIP = '202.72.1.77' and destIP='172.16.112.100' and packetime between '1999-04-05 18:36:11' and '1999-04-05 18:51:18' and destPort in (80)
UPDATE TCP_51_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.20' and packetime between '1999-04-05 18:57:21' and '1999-04-05 18:57:22' and destPort in (53)
UPDATE TCP_51_in SET category =1 where srcIP = '206.48.44.18' and destIP='172.16.115.234' and packetime between '1999-04-05 19:48:01' and '1999-04-05 20:04:42' and destPort in (139)
UPDATE TCP_51_in SET category =1 where srcIP = '172.16.112.50' and LEFT(destIP,11)='172.16.113.' and packetime between '1999-04-05 20:00:27' and '1999-04-05 20:15:27' and destPort in (7)
UPDATE TCP_51_in SET category =1 where srcIP = '135.13.216.191' and destIP='172.16.112.50' and packetime between '1999-04-05 20:17:12' and '1999-04-05 20:20:15' and destPort in (23)
UPDATE TCP_51_in SET category =1 where srcIP = '172.16.118.70' and destIP='172.16.114.50' and packetime between '1999-04-05 20:46:13' and '1999-04-05 20:47:42' and sourcePort in (20,21,25) and destPort in (23,113)
--
UPDATE TCP_52_in SET category =1 where srcIP = '135.8.60.182' and destIP='172.16.112.50' and packetime between '1999-04-06 08:11:15' and '1999-04-06 08:11:25' and destPort in (23)
UPDATE TCP_52_in SET category =1 where srcIP = '135.8.60.182' and destIP='172.16.112.50' and packetime between '1999-04-06 08:11:27' and '1999-04-06 08:22:05' and destPort in (23)
UPDATE TCP_52_in SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.114.50' and packetime between '1999-04-06 08:32:14' and '1999-04-06 08:47:15' and destPort in (23)
UPDATE TCP_52_in SET category =1 where srcIP = '172.16.113.204' and destIP='172.16.112.100' and packetime between '1999-04-06 08:53:17' and '1999-04-06 08:53:24' and destPort in (20,21,23)
UPDATE TCP_52_in SET category =1 where srcIP = '172.16.113.204' and destIP='172.16.112.100' and packetime between '1999-04-06 08:53:26' and '1999-04-06 09:10:42' and destPort in (20,21,23)
UPDATE TCP_52_in SET category =1 where srcIP = '194.7.248.153' and destIP='172.16.112.50' and packetime between '1999-04-06 09:19:01' and '1999-04-06 09:20:13'and destPort in (6000)
UPDATE TCP_52_in SET category =1 where srcIP = '172.16.113.204' and destIP='172.16.112.100' and packetime between '1999-04-06 09:33:15' and '1999-04-06 09:42:55' and destPort in (20,21,23)
UPDATE TCP_52_in SET category =1 where srcIP = '192.182.91.233' and destIP='172.16.112.50' and packetime between '1999-04-06 09:45:13' and '1999-04-06 09:48:16' and destPort in (23)
UPDATE TCP_52_in SET category =1 where srcIP = '152.169.215.104' and destIP='172.16.112.194' and packetime between '1999-04-06 10:07:18' and '1999-04-06 10:07:54'  and destPort in (20,21,23)
UPDATE TCP_52_in SET category =1 where srcIP = '172.16.114.207' and destIP='172.16.112.50' and packetime between '1999-04-06 10:19:16' and '1999-04-06 10:19:27'  and destPort in (20,21,513)
UPDATE TCP_52_in SET category =1 where srcIP = '172.16.114.207' and destIP='172.16.112.50' and packetime between '1999-04-06 10:32:48' and '1999-04-06 10:33:20' and destPort in (20,21,513)
UPDATE TCP_52_in SET category =1 where srcIP = '152.169.215.104' and destIP='172.16.112.194' and packetime between '1999-04-06 10:36:16' and '1999-04-06 10:48:01' and destPort in (20,21,513)
UPDATE TCP_52_in SET category =1 where srcIP = '199.227.99.125' and destIP='172.16.112.50' and packetime between '1999-04-06 11:20:09' and '1999-04-06 11:43:45' and sourcePort in (80,6000) and destPort in (23)
UPDATE TCP_52_in SET category =1 where srcIP = '206.48.44.50' and destIP='172.16.114.50' and packetime between '1999-04-06 11:31:21' and '1999-04-06 11:51:59' and sourcePort in (2222,2223,2284) and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '172.16.114.50' and destIP='206.48.44.50' and packetime between '1999-04-06 11:37:43' and '1999-04-06 11:37:44' and sourcePort in (2222,2223,2284) and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '10.20.30.40' and destIP='172.16.114.50' and packetime between '1999-04-06 11:38:04' and '1999-04-06 11:51:45' and destPort < 1025
UPDATE TCP_52_in SET category =1 where srcIP = '172.16.114.50' and destIP='206.48.44.50' and packetime between '1999-04-06 11:42:40' and '1999-04-06 11:42:41' and sourcePort in (2222,2223,2284) and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '172.16.114.50' and destIP='206.48.44.50' and packetime between '1999-04-06 11:47:03' and '1999-04-06 11:47:04' and sourcePort in (2222,2223,2284) and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '172.16.112.50' and destIP='196.37.75.158' and packetime between '1999-04-06 12:06:32' and '1999-04-06 12:10:02' and destPort in (8000)
UPDATE TCP_52_in SET category =1 where srcIP = '152.169.215.104' and destIP='172.16.112.50' and packetime between '1999-04-06 12:55:14' and '1999-04-06 13:11:46' and sourcePort in (20,21,25) and destPort in (23)
UPDATE TCP_52_in SET category =1 where srcIP = '199.227.99.125' and destIP='172.16.112.50' and packetime between '1999-04-06 12:59:00' and '1999-04-06 13:01:00'  and sourcePort in (80,6000) and destPort in (23)
UPDATE TCP_52_in SET category =1 where srcIP = '166.102.114.43' and destIP='172.16.113.50' and packetime between '1999-04-06 13:06:00' and '1999-04-06 13:06:30'
UPDATE TCP_52_in SET category =1 where srcIP = '194.7.248.153' and destIP='172.16.112.100' and packetime between '1999-04-06 13:28:11' and '1999-04-06 13:50:38' and destPort in (23,80)
UPDATE TCP_52_in SET category =1 where srcIP = '194.7.248.153' and destIP='172.16.112.100' and packetime between '1999-04-06 13:50:03' and '1999-04-06 14:05:08' and destPort in (23,80)
UPDATE TCP_52_in SET category =1 where srcIP = '194.7.248.153' and destIP='172.16.112.100' and packetime between '1999-04-06 13:58:10' and '1999-04-06 14:10:30' and destPort in (23,80)
UPDATE TCP_52_in SET category =1 where srcIP = '172.3.45.1' and destIP='172.16.112.50' and packetime between '1999-04-06 14:13:56' and '1999-04-06 14:13:57' and destPort in (514)
UPDATE TCP_52_in SET category =1 where srcIP = '207.103.80.104' and destIP='172.16.114.207' and packetime between '1999-04-06 14:24:17' and '1999-04-06 14:39:04' and destPort in (23)
UPDATE TCP_52_in SET category =1 where srcIP = '199.174.194.16' and destIP='172.16.112.100' and packetime between '1999-04-06 14:26:26' and '1999-04-06 14:26:37' and sourcePort in (137) and destPort in (25,80)--i
UPDATE TCP_52_in SET category =1 where srcIP = '199.174.194.16' and destIP='172.16.112.100' and packetime between '1999-04-06 14:34:11' and '1999-04-06 14:34:12' and sourcePort in (137) and destPort in (25,80)--i
UPDATE TCP_52_in SET category =1 where srcIP = '199.174.194.16' and destIP='172.16.112.100' and packetime between '1999-04-06 14:34:19' and '1999-04-06 14:34:20' and sourcePort in (137) and destPort in (25,80)--i
UPDATE TCP_52_in SET category =1 where srcIP = '199.174.194.16' and destIP='172.16.112.100' and packetime between '1999-04-06 14:34:41' and '1999-04-06 14:34:42' and sourcePort in (137) and destPort in (25,80)--i
UPDATE TCP_52_in SET category =1 where srcIP = '199.174.194.16' and destIP='172.16.112.100' and packetime between '1999-04-06 14:34:48' and '1999-04-06 14:34:49' and sourcePort in (137) and destPort in (25,80)--i
UPDATE TCP_52_in SET category =1 where srcIP = '199.174.194.16' and destIP='172.16.112.100' and packetime between '1999-04-06 14:36:19' and '1999-04-06 14:36:20' and sourcePort in (137) and destPort in (25,80)--i
UPDATE TCP_52_in SET category =1 where srcIP = '199.174.194.16' and destIP='172.16.112.100' and packetime between '1999-04-06 14:36:39' and '1999-04-06 14:36:40' and sourcePort in (137) and destPort in (25,80)--i
UPDATE TCP_52_in SET category =1 where srcIP = '199.174.194.16' and destIP='172.16.112.100' and packetime between '1999-04-06 14:36:47' and '1999-04-06 14:36:48' and sourcePort in (137) and destPort in (25,80)--i
UPDATE TCP_52_in SET category =1 where srcIP = '199.174.194.16' and destIP='172.16.112.100' and packetime between '1999-04-06 14:38:25' and '1999-04-06 14:38:26' and sourcePort in (137) and destPort in (25,80)--i
UPDATE TCP_52_in SET category =1 where srcIP = '199.174.194.16' and destIP='172.16.112.100' and packetime between '1999-04-06 14:38:34' and '1999-04-06 14:39:18' and sourcePort in (137) and destPort in (25,80)--i
UPDATE TCP_52_in SET category =1 where srcIP = '196.38.75.158' and destIP='172.16.112.50' and packetime between '1999-04-06 16:24:15' and '1999-04-06 16:24:48' and destPort in (20,21,23)
UPDATE TCP_52_in SET category =1 where srcIP = '196.38.75.158' and destIP='172.16.112.50' and packetime between '1999-04-06 16:40:15' and '1999-04-06 17:20:39' and destPort in (20,21,23)
UPDATE TCP_52_in SET category =1 where srcIP = '196.38.75.158' and destIP='172.16.113.50' and packetime between '1999-04-06 16:54:20' and '1999-04-06 16:54:21' and destPort in (20,21,23)
UPDATE TCP_52_in SET category =1 where srcIP = '196.38.75.158' and destIP='172.16.113.50' and packetime between '1999-04-06 16:54:22' and '1999-04-06 16:54:23' and destPort in (20,21,23)
UPDATE TCP_52_in SET category =1 where srcIP = '196.38.75.158' and destIP='172.16.113.50' and packetime between '1999-04-06 16:54:24' and '1999-04-06 16:54:25' and destPort in (20,21,23)
UPDATE TCP_52_in SET category =1 where srcIP = '196.38.75.158' and destIP='172.16.113.50' and packetime between '1999-04-06 16:54:45' and '1999-04-06 16:54:46' and destPort in (20,21,23)
UPDATE TCP_52_in SET category =1 where srcIP = '196.38.75.158' and destIP='172.16.113.50' and packetime between '1999-04-06 16:54:47' and '1999-04-06 16:54:48' and destPort in (20,21,23)
UPDATE TCP_52_in SET category =1 where srcIP = '196.38.75.158' and destIP='172.16.113.50' and packetime between '1999-04-06 16:54:49' and '1999-04-06 16:54:50' and destPort in (20,21,23)
UPDATE TCP_52_in SET category =1 where srcIP = '196.38.75.158' and destIP='172.16.113.50' and packetime between '1999-04-06 16:55:10' and '1999-04-06 16:55:11' and destPort in (20,21,23)
UPDATE TCP_52_in SET category =1 where srcIP = '196.38.75.158' and destIP='172.16.112.50' and packetime between '1999-04-06 17:22:15' and '1999-04-06 17:24:15' and destPort in (20,21,23)
UPDATE TCP_52_in SET category =1 where srcIP = '10.20.30.40' and destIP='192.168.1.1' and packetime between '1999-04-06 18:16:05' and '1999-04-06 18:19:31' and destPort<1025
UPDATE TCP_52_in SET category =1 where srcIP = '172.16.115.234' and destIP='172.16.112.100' and packetime between '1999-04-06 20:57:03' and '1999-04-06 21:13:36' and destPort in (139)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.148' and packetime between '1999-04-06 21:15:54' and '1999-04-06 21:15:57' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.148' and packetime between '1999-04-06 21:16:00' and '1999-04-06 21:16:03' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.148' and packetime between '1999-04-06 21:16:06' and '1999-04-06 21:16:09' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.148' and packetime between '1999-04-06 21:16:12' and '1999-04-06 21:16:15' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.148' and packetime between '1999-04-06 21:16:18' and '1999-04-06 21:16:21' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.100' and packetime between '1999-04-06 21:16:24' and '1999-04-06 21:16:27' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.100' and packetime between '1999-04-06 21:16:30' and '1999-04-06 21:16:33' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.100' and packetime between '1999-04-06 21:16:36' and '1999-04-06 21:16:39' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.100' and packetime between '1999-04-06 21:16:42' and '1999-04-06 21:16:45' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.100' and packetime between '1999-04-06 21:16:48' and '1999-04-06 21:16:51' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.10' and packetime between '1999-04-06 21:16:54' and '1999-04-06 21:16:57' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.10' and packetime between '1999-04-06 21:17:00' and '1999-04-06 21:17:03' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.10' and packetime between '1999-04-06 21:17:06' and '1999-04-06 21:17:09' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.10' and packetime between '1999-04-06 21:17:12' and '1999-04-06 21:17:15' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.10' and packetime between '1999-04-06 21:17:18' and '1999-04-06 21:17:21' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.20' and packetime between '1999-04-06 21:17:24' and '1999-04-06 21:17:27' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.20' and packetime between '1999-04-06 21:17:30' and '1999-04-06 21:17:33' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.20' and packetime between '1999-04-06 21:17:36' and '1999-04-06 21:17:39' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.20' and packetime between '1999-04-06 21:17:42' and '1999-04-06 21:17:45' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.20' and packetime between '1999-04-06 21:17:48' and '1999-04-06 21:17:51' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.30' and packetime between '1999-04-06 21:17:54' and '1999-04-06 21:17:57' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.30' and packetime between '1999-04-06 21:18:00' and '1999-04-06 21:18:03' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.30' and packetime between '1999-04-06 21:18:06' and '1999-04-06 21:18:09' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.30' and packetime between '1999-04-06 21:18:12' and '1999-04-06 21:18:15' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.30' and packetime between '1999-04-06 21:18:18' and '1999-04-06 21:18:21' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.40' and packetime between '1999-04-06 21:18:24' and '1999-04-06 21:18:27' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.40' and packetime between '1999-04-06 21:18:30' and '1999-04-06 21:18:33' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.40' and packetime between '1999-04-06 21:18:36' and '1999-04-06 21:18:39' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.40' and packetime between '1999-04-06 21:18:42' and '1999-04-06 21:18:45' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.40' and packetime between '1999-04-06 21:18:48' and '1999-04-06 21:18:51' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.50' and packetime between '1999-04-06 21:18:54' and '1999-04-06 21:18:57' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.50' and packetime between '1999-04-06 21:19:00' and '1999-04-06 21:19:03' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.50' and packetime between '1999-04-06 21:19:06' and '1999-04-06 21:19:09' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.50' and packetime between '1999-04-06 21:19:12' and '1999-04-06 21:19:15' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.50' and packetime between '1999-04-06 21:19:18' and '1999-04-06 21:19:21' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.60' and packetime between '1999-04-06 21:19:24' and '1999-04-06 21:19:27' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.60' and packetime between '1999-04-06 21:19:30' and '1999-04-06 21:19:33' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.60' and packetime between '1999-04-06 21:19:36' and '1999-04-06 21:19:39' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.60' and packetime between '1999-04-06 21:19:42' and '1999-04-06 21:19:45' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.60' and packetime between '1999-04-06 21:19:48' and '1999-04-06 21:19:51' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.70' and packetime between '1999-04-06 21:19:55' and '1999-04-06 21:19:58' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.70' and packetime between '1999-04-06 21:20:01' and '1999-04-06 21:20:04' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.70' and packetime between '1999-04-06 21:20:07' and '1999-04-06 21:20:10' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.70' and packetime between '1999-04-06 21:20:13' and '1999-04-06 21:20:16' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.70' and packetime between '1999-04-06 21:20:19' and '1999-04-06 21:20:22' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.80' and packetime between '1999-04-06 21:20:25' and '1999-04-06 21:20:28' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.80' and packetime between '1999-04-06 21:20:31' and '1999-04-06 21:20:34' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.80' and packetime between '1999-04-06 21:20:37' and '1999-04-06 21:20:40' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.80' and packetime between '1999-04-06 21:20:43' and '1999-04-06 21:20:46' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.80' and packetime between '1999-04-06 21:20:49' and '1999-04-06 21:20:52' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.90' and packetime between '1999-04-06 21:20:55' and '1999-04-06 21:20:58' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.90' and packetime between '1999-04-06 21:21:01' and '1999-04-06 21:21:04' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.90' and packetime between '1999-04-06 21:21:07' and '1999-04-06 21:21:10' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.90' and packetime between '1999-04-06 21:21:13' and '1999-04-06 21:21:16' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.90' and packetime between '1999-04-06 21:21:19' and '1999-04-06 21:21:22' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.20' and packetime between '1999-04-06 21:21:25' and '1999-04-06 21:21:28' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.20' and packetime between '1999-04-06 21:21:31' and '1999-04-06 21:21:34' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.20' and packetime between '1999-04-06 21:21:37' and '1999-04-06 21:21:40' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.20' and packetime between '1999-04-06 21:21:43' and '1999-04-06 21:21:46' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.20' and packetime between '1999-04-06 21:21:49' and '1999-04-06 21:21:52' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.169' and packetime between '1999-04-06 21:21:55' and '1999-04-06 21:21:58' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.169' and packetime between '1999-04-06 21:22:01' and '1999-04-06 21:22:04' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.169' and packetime between '1999-04-06 21:22:07' and '1999-04-06 21:22:10' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.169' and packetime between '1999-04-06 21:22:13' and '1999-04-06 21:22:16' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.169' and packetime between '1999-04-06 21:22:19' and '1999-04-06 21:22:22' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.207' and packetime between '1999-04-06 21:22:25' and '1999-04-06 21:22:28' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.207' and packetime between '1999-04-06 21:22:31' and '1999-04-06 21:22:34' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.207' and packetime between '1999-04-06 21:22:37' and '1999-04-06 21:22:40' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.207' and packetime between '1999-04-06 21:22:43' and '1999-04-06 21:22:46' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.207' and packetime between '1999-04-06 21:22:49' and '1999-04-06 21:22:52' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.84' and packetime between '1999-04-06 21:22:55' and '1999-04-06 21:22:58' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.84' and packetime between '1999-04-06 21:23:01' and '1999-04-06 21:23:04' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.84' and packetime between '1999-04-06 21:23:07' and '1999-04-06 21:23:10' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.84' and packetime between '1999-04-06 21:23:13' and '1999-04-06 21:23:16' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.84' and packetime between '1999-04-06 21:23:19' and '1999-04-06 21:23:22' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.0.1' and packetime between '1999-04-06 21:23:25' and '1999-04-06 21:23:28' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.0.1' and packetime between '1999-04-06 21:23:31' and '1999-04-06 21:23:34' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.0.1' and packetime between '1999-04-06 21:23:37' and '1999-04-06 21:23:40' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.0.1' and packetime between '1999-04-06 21:23:43' and '1999-04-06 21:23:46' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.0.1' and packetime between '1999-04-06 21:23:49' and '1999-04-06 21:23:52' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.194' and packetime between '1999-04-06 21:23:55' and '1999-04-06 21:23:58' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.194' and packetime between '1999-04-06 21:24:01' and '1999-04-06 21:24:04' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.194' and packetime between '1999-04-06 21:24:07' and '1999-04-06 21:24:10' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.194' and packetime between '1999-04-06 21:24:13' and '1999-04-06 21:24:16' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.194' and packetime between '1999-04-06 21:24:19' and '1999-04-06 21:24:22' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.115.234' and packetime between '1999-04-06 21:24:25' and '1999-04-06 21:24:28' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.115.234' and packetime between '1999-04-06 21:24:31' and '1999-04-06 21:24:34' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.115.234' and packetime between '1999-04-06 21:24:37' and '1999-04-06 21:24:40' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.115.234' and packetime between '1999-04-06 21:24:43' and '1999-04-06 21:24:46' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.115.234' and packetime between '1999-04-06 21:24:49' and '1999-04-06 21:24:52' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.115.5' and packetime between '1999-04-06 21:24:55' and '1999-04-06 21:24:58' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.115.5' and packetime between '1999-04-06 21:25:01' and '1999-04-06 21:25:04' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.115.5' and packetime between '1999-04-06 21:25:07' and '1999-04-06 21:25:10' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.115.5' and packetime between '1999-04-06 21:25:13' and '1999-04-06 21:25:16' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.115.5' and packetime between '1999-04-06 21:25:19' and '1999-04-06 21:25:22' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.115.87' and packetime between '1999-04-06 21:25:25' and '1999-04-06 21:25:28' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.115.87' and packetime between '1999-04-06 21:25:31' and '1999-04-06 21:25:34' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.115.87' and packetime between '1999-04-06 21:25:37' and '1999-04-06 21:25:40' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.115.87' and packetime between '1999-04-06 21:25:43' and '1999-04-06 21:25:46' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.115.87' and packetime between '1999-04-06 21:25:49' and '1999-04-06 21:25:52' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.116.194' and packetime between '1999-04-06 21:25:55' and '1999-04-06 21:25:58' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.116.194' and packetime between '1999-04-06 21:26:01' and '1999-04-06 21:26:04' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.116.194' and packetime between '1999-04-06 21:26:07' and '1999-04-06 21:26:10' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.116.194' and packetime between '1999-04-06 21:26:13' and '1999-04-06 21:26:16' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.116.194' and packetime between '1999-04-06 21:26:20' and '1999-04-06 21:26:23' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.116.201' and packetime between '1999-04-06 21:26:26' and '1999-04-06 21:26:29' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.116.201' and packetime between '1999-04-06 21:26:32' and '1999-04-06 21:26:35' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.116.201' and packetime between '1999-04-06 21:26:38' and '1999-04-06 21:26:41' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.116.201' and packetime between '1999-04-06 21:26:44' and '1999-04-06 21:26:47' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.116.201' and packetime between '1999-04-06 21:26:50' and '1999-04-06 21:26:53' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.116.44' and packetime between '1999-04-06 21:26:56' and '1999-04-06 21:26:59' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.116.44' and packetime between '1999-04-06 21:27:02' and '1999-04-06 21:27:05' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.116.44' and packetime between '1999-04-06 21:27:08' and '1999-04-06 21:27:11' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.116.44' and packetime between '1999-04-06 21:27:14' and '1999-04-06 21:27:17' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.116.44' and packetime between '1999-04-06 21:27:20' and '1999-04-06 21:27:23' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.10' and packetime between '1999-04-06 21:27:26' and '1999-04-06 21:27:29' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.10' and packetime between '1999-04-06 21:27:32' and '1999-04-06 21:27:35' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.10' and packetime between '1999-04-06 21:27:38' and '1999-04-06 21:27:41' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.10' and packetime between '1999-04-06 21:27:44' and '1999-04-06 21:27:47' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.10' and packetime between '1999-04-06 21:27:50' and '1999-04-06 21:27:53' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.132' and packetime between '1999-04-06 21:27:56' and '1999-04-06 21:27:59' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.132' and packetime between '1999-04-06 21:28:02' and '1999-04-06 21:28:05' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.132' and packetime between '1999-04-06 21:28:08' and '1999-04-06 21:28:11' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.132' and packetime between '1999-04-06 21:28:14' and '1999-04-06 21:28:17' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.132' and packetime between '1999-04-06 21:28:20' and '1999-04-06 21:28:23' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.52' and packetime between '1999-04-06 21:28:26' and '1999-04-06 21:28:29' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.52' and packetime between '1999-04-06 21:28:32' and '1999-04-06 21:28:35' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.52' and packetime between '1999-04-06 21:28:38' and '1999-04-06 21:28:41' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.52' and packetime between '1999-04-06 21:28:44' and '1999-04-06 21:28:47' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.52' and packetime between '1999-04-06 21:28:50' and '1999-04-06 21:28:53' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.168' and packetime between '1999-04-06 21:28:56' and '1999-04-06 21:28:59' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.168' and packetime between '1999-04-06 21:29:02' and '1999-04-06 21:29:05' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.168' and packetime between '1999-04-06 21:29:08' and '1999-04-06 21:29:11' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.168' and packetime between '1999-04-06 21:29:14' and '1999-04-06 21:29:17' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.168' and packetime between '1999-04-06 21:29:20' and '1999-04-06 21:29:23' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.111' and packetime between '1999-04-06 21:29:26' and '1999-04-06 21:29:29' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.111' and packetime between '1999-04-06 21:29:32' and '1999-04-06 21:29:35' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.111' and packetime between '1999-04-06 21:29:38' and '1999-04-06 21:29:41' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.111' and packetime between '1999-04-06 21:29:44' and '1999-04-06 21:29:47' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.111' and packetime between '1999-04-06 21:29:50' and '1999-04-06 21:29:53' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.103' and packetime between '1999-04-06 21:29:56' and '1999-04-06 21:29:59' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.103' and packetime between '1999-04-06 21:30:02' and '1999-04-06 21:30:05' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.103' and packetime between '1999-04-06 21:30:08' and '1999-04-06 21:30:11' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.103' and packetime between '1999-04-06 21:30:14' and '1999-04-06 21:30:17' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.103' and packetime between '1999-04-06 21:30:20' and '1999-04-06 21:30:23' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.200' and packetime between '1999-04-06 21:30:26' and '1999-04-06 21:30:29' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.200' and packetime between '1999-04-06 21:30:32' and '1999-04-06 21:30:35' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.200' and packetime between '1999-04-06 21:30:38' and '1999-04-06 21:30:41' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.200' and packetime between '1999-04-06 21:30:44' and '1999-04-06 21:30:47' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.200' and packetime between '1999-04-06 21:30:50' and '1999-04-06 21:30:53' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.105' and packetime between '1999-04-06 21:30:56' and '1999-04-06 21:30:59' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.105' and packetime between '1999-04-06 21:31:02' and '1999-04-06 21:31:05' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.105' and packetime between '1999-04-06 21:31:08' and '1999-04-06 21:31:11' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.105' and packetime between '1999-04-06 21:31:14' and '1999-04-06 21:31:17' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.105' and packetime between '1999-04-06 21:31:20' and '1999-04-06 21:31:23' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.204' and packetime between '1999-04-06 21:31:26' and '1999-04-06 21:31:29' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.204' and packetime between '1999-04-06 21:31:32' and '1999-04-06 21:31:35' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.204' and packetime between '1999-04-06 21:31:38' and '1999-04-06 21:31:41' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.204' and packetime between '1999-04-06 21:31:44' and '1999-04-06 21:31:47' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.204' and packetime between '1999-04-06 21:31:50' and '1999-04-06 21:31:53' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.149' and packetime between '1999-04-06 21:31:56' and '1999-04-06 21:31:59' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.149' and packetime between '1999-04-06 21:32:02' and '1999-04-06 21:32:05' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.149' and packetime between '1999-04-06 21:32:08' and '1999-04-06 21:32:11' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.149' and packetime between '1999-04-06 21:32:14' and '1999-04-06 21:32:17' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.149' and packetime between '1999-04-06 21:32:20' and '1999-04-06 21:32:23' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.207' and packetime between '1999-04-06 21:32:27' and '1999-04-06 21:32:30' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.207' and packetime between '1999-04-06 21:32:33' and '1999-04-06 21:32:36' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.207' and packetime between '1999-04-06 21:32:39' and '1999-04-06 21:32:42' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.207' and packetime between '1999-04-06 21:32:45' and '1999-04-06 21:32:48' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.207' and packetime between '1999-04-06 21:32:51' and '1999-04-06 21:32:54' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.100' and packetime between '1999-04-06 21:32:57' and '1999-04-06 21:33:00' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.100' and packetime between '1999-04-06 21:33:03' and '1999-04-06 21:33:06' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.100' and packetime between '1999-04-06 21:33:09' and '1999-04-06 21:33:12' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.100' and packetime between '1999-04-06 21:33:15' and '1999-04-06 21:33:18' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.100' and packetime between '1999-04-06 21:33:21' and '1999-04-06 21:33:24' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.50' and packetime between '1999-04-06 21:33:27' and '1999-04-06 21:33:30' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.50' and packetime between '1999-04-06 21:33:33' and '1999-04-06 21:33:36' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.50' and packetime between '1999-04-06 21:33:39' and '1999-04-06 21:33:42' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.50' and packetime between '1999-04-06 21:33:45' and '1999-04-06 21:33:48' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.50' and packetime between '1999-04-06 21:33:51' and '1999-04-06 21:33:54' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.50' and packetime between '1999-04-06 21:33:57' and '1999-04-06 21:34:00' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.50' and packetime between '1999-04-06 21:34:03' and '1999-04-06 21:34:06' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.50' and packetime between '1999-04-06 21:34:09' and '1999-04-06 21:34:12' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.50' and packetime between '1999-04-06 21:34:15' and '1999-04-06 21:34:18' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.50' and packetime between '1999-04-06 21:34:21' and '1999-04-06 21:34:24' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.50' and packetime between '1999-04-06 21:34:27' and '1999-04-06 21:34:30' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.50' and packetime between '1999-04-06 21:34:33' and '1999-04-06 21:34:36' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.50' and packetime between '1999-04-06 21:34:39' and '1999-04-06 21:34:42' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.50' and packetime between '1999-04-06 21:34:45' and '1999-04-06 21:34:48' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.50' and packetime between '1999-04-06 21:34:51' and '1999-04-06 21:34:54' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.50' and packetime between '1999-04-06 21:34:57' and '1999-04-06 21:35:00' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.50' and packetime between '1999-04-06 21:35:03' and '1999-04-06 21:35:06' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.50' and packetime between '1999-04-06 21:35:09' and '1999-04-06 21:35:12' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.50' and packetime between '1999-04-06 21:35:15' and '1999-04-06 21:35:18' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.50' and packetime between '1999-04-06 21:35:21' and '1999-04-06 21:35:24' and destPort in (80)
UPDATE TCP_52_in SET category =1 where srcIP = '172.16.118.20' and destIP='172.16.114.50' and packetime between '1999-04-06 21:45:02' and '1999-04-06 21:46:30' and sourcePort in (20,21,25) and destPort in (23)
UPDATE TCP_52_in SET category =1 where srcIP = '172.16.114.50' and destIP='172.16.118.20' and packetime between '1999-04-06 21:45:24' and '1999-04-06 21:46:10' and destPort in (80)
--
UPDATE TCP_53_in SET category =1 where srcIP = '135.8.60.182' and destIP='172.16.112.50' and packetime between '1999-04-07 05:04:19' and '1999-04-07 05:08:21' and destPort in (23)
UPDATE TCP_53_in SET category =1 where srcIP = '152.204.242.193' and destIP='172.16.112.50' and packetime between '1999-04-07 08:46:02' and '1999-04-07 08:46:27' and destPort in (6000)
UPDATE TCP_53_in SET category =1 where srcIP = '209.1.12.46' and destIP='172.16.114.50' and packetime between '1999-04-07 08:58:16' and '1999-04-07 08:58:17' and destPort in (80)
UPDATE TCP_53_in SET category =1 where destIP='172.16.112.50' and packetime between '1999-04-07 09:44:00' and '1999-04-07 09:59:00'--src console
UPDATE TCP_53_in SET category =1 where srcIP = '209.167.99.71' and destIP='172.16.112.100' and packetime between '1999-04-07 09:50:33' and '1999-04-07 09:50:38' and destPort in (25,12345,12346)
UPDATE TCP_53_in SET category =1 where srcIP = '152.204.242.193' and destIP='172.16.114.50' and packetime between '1999-04-07 10:26:12' and '1999-04-07 10:26:16' and destPort in (80)
UPDATE TCP_53_in SET category =1 where srcIP = '172.16.113.84' and destIP='197.182.91.233' and packetime between '1999-04-07 11:06:56' and '1999-04-07 11:06:57' and destPort in (25)
UPDATE TCP_53_in SET category =1 where srcIP = '197.182.91.233' and destIP='172.16.114.50' and packetime between '1999-04-07 11:32:16' and '1999-04-07 11:32:17' and destPort in (23)
UPDATE TCP_53_in SET category =1 where srcIP = '197.182.91.233' and destIP='172.16.114.50' and packetime between '1999-04-07 11:34:17' and '1999-04-07 11:34:18' and destPort in (23)
UPDATE TCP_53_in SET category =1 where srcIP = '197.182.91.233' and destIP='172.16.114.50' and packetime between '1999-04-07 11:36:18' and '1999-04-07 11:36:19'  and destPort in (23)
UPDATE TCP_53_in SET category =1 where srcIP = '197.182.91.233' and destIP='172.16.114.50' and packetime between '1999-04-07 11:38:39' and '1999-04-07 11:38:40'  and destPort in (23)
UPDATE TCP_53_in SET category =1 where srcIP = '197.182.91.233' and destIP='172.16.114.50' and packetime between '1999-04-07 11:40:40' and '1999-04-07 11:40:41'  and destPort in (23)
UPDATE TCP_53_in SET category =1 where srcIP = '197.182.91.233' and destIP='172.16.114.50' and packetime between '1999-04-07 11:43:00' and '1999-04-07 11:43:01'  and destPort in (23)
UPDATE TCP_53_in SET category =1 where srcIP = '197.182.91.233' and destIP='172.16.114.50' and packetime between '1999-04-07 11:45:20' and '1999-04-07 11:45:21'  and destPort in (23)
UPDATE TCP_53_in SET category =1 where srcIP = '209.167.99.71' and destIP='172.16.112.100' and packetime between '1999-04-07 12:03:45' and '1999-04-07 12:05:01' and destPort in (25,12345,12346)
UPDATE TCP_53_in SET category =1 where srcIP = '204.97.153.43' and destIP='172.16.114.50' and packetime between '1999-04-07 12:37:10' and '1999-04-07 12:37:11' and destPort <11
UPDATE TCP_53_in SET category =1 where srcIP = '204.97.153.43' and destIP='172.16.114.50' and packetime between '1999-04-07 12:37:16' and '1999-04-07 12:37:17' and destPort <11
UPDATE TCP_53_in SET category =1 where srcIP = '204.97.153.43' and destIP='172.16.114.50' and packetime between '1999-04-07 12:38:16' and '1999-04-07 12:38:17' and destPort <11
UPDATE TCP_53_in SET category =1 where srcIP = '204.97.153.43' and destIP='172.16.114.50' and packetime between '1999-04-07 12:39:16' and '1999-04-07 12:39:17' and destPort <11
UPDATE TCP_53_in SET category =1 where srcIP = '204.97.153.43' and destIP='172.16.114.50' and packetime between '1999-04-07 12:40:16' and '1999-04-07 12:40:17' and destPort <11
UPDATE TCP_53_in SET category =1 where srcIP = '204.97.153.43' and destIP='172.16.114.50' and packetime between '1999-04-07 12:41:16' and '1999-04-07 12:41:17' and destPort <11
UPDATE TCP_53_in SET category =1 where srcIP = '204.97.153.43' and destIP='172.16.114.50' and packetime between '1999-04-07 12:42:17' and '1999-04-07 12:42:18' and destPort <11
UPDATE TCP_53_in SET category =1 where srcIP = '204.97.153.43' and destIP='172.16.114.50' and packetime between '1999-04-07 12:43:17' and '1999-04-07 12:43:18' and destPort <11
UPDATE TCP_53_in SET category =1 where srcIP = '204.97.153.43' and destIP='172.16.114.50' and packetime between '1999-04-07 12:43:23' and '1999-04-07 12:43:24' and destPort <11
UPDATE TCP_53_in SET category =1 where srcIP = '204.97.153.43' and destIP='172.16.114.50' and packetime between '1999-04-07 12:44:29' and '1999-04-07 12:44:30' and destPort <11
UPDATE TCP_53_in SET category =1 where srcIP = '204.97.153.43' and destIP='172.16.114.50' and packetime between '1999-04-07 12:45:29' and '1999-04-07 12:45:30' and destPort <11
UPDATE TCP_53_in SET category =1 where srcIP = '204.97.153.43' and destIP='172.16.114.50' and packetime between '1999-04-07 12:45:35' and '1999-04-07 12:45:36' and destPort <11
UPDATE TCP_53_in SET category =1 where srcIP = '204.97.153.43' and destIP='172.16.114.50' and packetime between '1999-04-07 12:46:41' and '1999-04-07 12:46:42' and destPort <11
UPDATE TCP_53_in SET category =1 where srcIP = '209.17.189.98' and destIP='172.16.112.207' and packetime between '1999-04-07 13:33:17' and '1999-04-07 13:44:03'  and destPort in (23)
UPDATE TCP_53_in SET category =1 where srcIP = '172.16.114.169' and destIP='172.16.112.50' and packetime between '1999-04-07 13:40:24' and '1999-04-07 13:40:25'  and destPort in (25)
UPDATE TCP_53_in SET category =1 where srcIP = '172.16.114.169' and destIP='172.16.112.50' and packetime between '1999-04-07 13:43:25' and '1999-04-07 13:43:26'  and destPort in (25)
UPDATE TCP_53_in SET category =1 where srcIP = '172.16.114.169' and destIP='172.16.112.50' and packetime between '1999-04-07 13:46:45' and '1999-04-07 13:46:46'  and destPort in (25)
UPDATE TCP_53_in SET category =1 where srcIP = '172.16.114.169' and destIP='172.16.112.50' and packetime between '1999-04-07 13:50:05' and '1999-04-07 13:50:06'  and destPort in (25)
UPDATE TCP_53_in SET category =1 where srcIP = '172.16.114.169' and destIP='172.16.112.50' and packetime between '1999-04-07 13:53:25' and '1999-04-07 13:53:26'  and destPort in (25)
UPDATE TCP_53_in SET category =1 where srcIP = '172.16.114.169' and destIP='172.16.112.50' and packetime between '1999-04-07 13:56:29' and '1999-04-07 13:56:30'  and destPort in (25)
UPDATE TCP_53_in SET category =1 where srcIP = '172.16.114.169' and destIP='172.16.112.50' and packetime between '1999-04-07 13:59:33' and '1999-04-07 13:59:34'  and destPort in (25)
UPDATE TCP_53_in SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:49:35' and '1999-04-07 14:49:37'  and destPort in (161)
UPDATE TCP_53_in SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:49:42' and '1999-04-07 14:49:43'  and destPort in (161)
UPDATE TCP_53_in SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:49:47' and '1999-04-07 14:49:48'  and destPort in (161)
UPDATE TCP_53_in SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:49:52' and '1999-04-07 14:49:53'  and destPort in (161)
UPDATE TCP_53_in SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:49:57' and '1999-04-07 14:49:58'  and destPort in (161)
UPDATE TCP_53_in SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:50:02' and '1999-04-07 14:50:03'  and destPort in (161)
UPDATE TCP_53_in SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:50:07' and '1999-04-07 14:50:08'  and destPort in (161)
UPDATE TCP_53_in SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:50:12' and '1999-04-07 14:50:13'  and destPort in (161)
UPDATE TCP_53_in SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:50:18' and '1999-04-07 14:50:19'  and destPort in (161)
UPDATE TCP_53_in SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:50:23' and '1999-04-07 14:50:24'  and destPort in (161)
UPDATE TCP_53_in SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:50:28' and '1999-04-07 14:50:29'  and destPort in (161)
UPDATE TCP_53_in SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:50:33' and '1999-04-07 14:50:34'  and destPort in (161)
UPDATE TCP_53_in SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:50:38' and '1999-04-07 14:50:39'  and destPort in (161)
UPDATE TCP_53_in SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:50:43' and '1999-04-07 14:50:44'  and destPort in (161)
UPDATE TCP_53_in SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:50:48' and '1999-04-07 14:50:49'  and destPort in (161)
UPDATE TCP_53_in SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:50:53' and '1999-04-07 14:50:54'  and destPort in (161)
UPDATE TCP_53_in SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:50:58' and '1999-04-07 14:50:59'  and destPort in (161)
UPDATE TCP_53_in SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:51:03' and '1999-04-07 14:51:04'  and destPort in (161)
UPDATE TCP_53_in SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:51:08' and '1999-04-07 14:51:09'  and destPort in (161)
UPDATE TCP_53_in SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:51:13' and '1999-04-07 14:51:14'  and destPort in (161)
UPDATE TCP_53_in SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:51:19' and '1999-04-07 14:51:20'  and destPort in (161)
UPDATE TCP_53_in SET category =1 where srcIP = '172.16.117.52' and destIP='172.16.113.50' and packetime between '1999-04-07 15:01:16' and '1999-04-07 15:32:21'  and destPort in (25)
UPDATE TCP_53_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.114.50' and packetime between '1999-04-07 15:26:15' and '1999-04-07 15:28:04'  and destPort in (80)
UPDATE TCP_53_in SET category =1 where srcIP = '195.115.218.108' and destIP='172.16.112.50' and packetime between '1999-04-07 15:54:19' and '1999-04-07 15:54:20'  and destPort in (23,25)
UPDATE TCP_53_in SET category =1 where srcIP = '195.115.218.108' and destIP='172.16.112.50' and packetime between '1999-04-07 15:59:19' and '1999-04-07 22:50:59'  and destPort in (23,25)
UPDATE TCP_53_in SET category =1 where srcIP = '172.16.117.52' and destIP='172.16.114.50' and packetime between '1999-04-07 17:13:17' and '1999-04-07 17:21:56'  and destPort in (80)
UPDATE TCP_53_in SET category =1 where srcIP = '209.30.71.165' and destIP='172.16.112.50' and packetime between '1999-04-07 19:51:19' and '1999-04-07 19:51:24'  and destPort < 101 and destPort <>53
UPDATE TCP_53_in SET category =1 where srcIP = '209.30.71.165' and destIP='172.16.112.50' and packetime between '1999-04-07 19:51:25' and '1999-04-07 19:51:39'  and destPort < 101 and destPort <>53
UPDATE TCP_53_in SET category =1 where srcIP = '209.30.71.165' and destIP='172.16.112.50' and packetime between '1999-04-07 19:51:40' and '1999-04-07 19:51:51'  and destPort < 101 and destPort <>53
UPDATE TCP_53_in SET category =1 where srcIP = '209.30.71.165' and destIP='172.16.112.50' and packetime between '1999-04-07 19:51:52' and '1999-04-07 19:52:05'  and destPort < 101 and destPort <>53
UPDATE TCP_53_in SET category =1 where srcIP = '209.30.71.165' and destIP='172.16.112.50' and packetime between '1999-04-07 19:52:06' and '1999-04-07 19:52:15'  and destPort < 101 and destPort <>53
UPDATE TCP_53_in SET category =1 where srcIP = '209.30.71.165' and destIP='172.16.112.50' and packetime between '1999-04-07 19:52:16' and '1999-04-07 19:52:19'  and destPort < 101 and destPort <>53
UPDATE TCP_53_in SET category =1 where srcIP = '209.30.71.165' and destIP='172.16.112.50' and packetime between '1999-04-07 19:52:20' and '1999-04-07 19:52:35'  and destPort < 101 and destPort <>53
UPDATE TCP_53_in SET category =1 where srcIP = '209.30.71.165' and destIP='172.16.112.50' and packetime between '1999-04-07 19:52:36' and '1999-04-07 19:52:48'  and destPort < 101 and destPort <>53
UPDATE TCP_53_in SET category =1 where srcIP = '209.30.71.165' and destIP='172.16.112.50' and packetime between '1999-04-07 19:52:49' and '1999-04-07 19:53:02'  and destPort < 101 and destPort <>53
UPDATE TCP_53_in SET category =1 where srcIP = '209.30.71.165' and destIP='172.16.112.50' and packetime between '1999-04-07 19:53:03' and '1999-04-07 19:53:07'  and destPort < 101 and destPort <>53
--
UPDATE TCP_54_in SET category =1 where destIP='172.16.112.50' and packetime between '1999-04-08 08:33:00' and '1999-04-08 08:36:00'
UPDATE TCP_54_in SET category =1 where srcIP = '206.48.44.50' and destIP='172.16.114.50' and packetime between '1999-04-08 09:01:08' and '1999-04-08 09:01:13' and destPort in (80) 
UPDATE TCP_54_in SET category =1 where srcIP = '172.16.112.149' and destIP='172.16.112.100' and packetime between '1999-04-08 09:16:20' and '1999-04-08 09:17:38' and destPort in (20,21,23)
UPDATE TCP_54_in SET category =1 where srcIP = '172.16.112.149' and destIP='172.16.112.100' and packetime between '1999-04-08 09:17:52' and '1999-04-08 09:27:35'  and destPort in (20,21,23)
UPDATE TCP_54_in SET category =1 where srcIP = '206.48.44.50' and destIP='172.16.114.50' and packetime between '1999-04-08 09:31:33' and '1999-04-08 09:31:41' and destPort in (80) 
UPDATE TCP_54_in SET category =1 where srcIP = '206.48.44.50' and destIP='172.16.114.50' and packetime between '1999-04-08 09:31:43' and '1999-04-08 09:31:49' and destPort in (80) 
UPDATE TCP_54_in SET category =1 where srcIP = '206.48.44.50' and destIP='172.16.114.50' and packetime between '1999-04-08 09:32:03' and '1999-04-08 09:32:10' and destPort in (80) 
UPDATE TCP_54_in SET category =1 where srcIP = '206.48.44.50' and destIP='172.16.114.50' and packetime between '1999-04-08 09:32:19' and '1999-04-08 09:32:30' and destPort in (80) 
UPDATE TCP_54_in SET category =1 where srcIP = '206.48.44.50' and destIP='172.16.114.50' and packetime between '1999-04-08 09:32:37' and '1999-04-08 09:32:42' and destPort in (80) 
UPDATE TCP_54_in SET category =1 where srcIP = '206.48.44.50' and destIP='172.16.114.50' and packetime between '1999-04-08 09:32:48' and '1999-04-08 09:32:54' and destPort in (80) 
UPDATE TCP_54_in SET category =1 where srcIP = '172.16.112.100' and destIP='172.16.112.100' and packetime between '1999-04-08 10:21:00' and '1999-04-08 10:36:00' --i
UPDATE TCP_54_in SET category =1 where srcIP = '153.10.8.174' and destIP='172.16.112.50' and packetime between '1999-04-08 10:34:11' and '1999-04-08 10:34:12'  and destPort in (22,79,514)
UPDATE TCP_54_in SET category =1 where srcIP = '153.10.8.174' and destIP='172.16.112.50' and packetime between '1999-04-08 10:37:02' and '1999-04-08 10:37:03'  and destPort in (22,79,514)
UPDATE TCP_54_in SET category =1 where srcIP = '153.10.8.174' and destIP='172.16.112.50' and packetime between '1999-04-08 10:39:54' and '1999-04-08 10:39:55'  and destPort in (22,79,514)
UPDATE TCP_54_in SET category =1 where srcIP = '172.16.112.149' and destIP='172.16.112.100' and packetime between '1999-04-08 11:14:29' and '1999-04-08 11:20:07' and destPort in (20,21,23)
UPDATE TCP_54_in SET category =1 where srcIP = '206.48.44.18' and destIP='172.16.112.100' and packetime between '1999-04-08 11:26:37' and '1999-04-08 11:42:46' and destPort in (20,21,23,80,139)
UPDATE TCP_54_in SET category =1 where srcIP = '194.7.248.153' and destIP='172.16.112.100' and packetime between '1999-04-08 11:52:05' and '1999-04-08 11:57:36' and destPort in (23,80)
UPDATE TCP_54_in SET category =1 where srcIP = '194.7.248.153' and destIP='172.16.112.100' and packetime between '1999-04-08 11:57:01' and '1999-04-08 12:12:04' and destPort in (23,80)
UPDATE TCP_54_in SET category =1 where srcIP = '194.7.248.153' and destIP='172.16.112.100' and packetime between '1999-04-08 12:04:20' and '1999-04-08 12:07:44' and destPort in (23,80)
UPDATE TCP_54_in SET category =1 where srcIP = '172.16.112.50' and destIP='196.37.75.158' and packetime between '1999-04-08 12:06:30' and '1999-04-08 12:06:31' and destPort in (8000) 
UPDATE TCP_54_in SET category =1 where srcIP = '172.16.112.50' and destIP='196.37.75.158' and packetime between '1999-04-08 12:07:00' and '1999-04-08 12:07:01' and destPort in (8000) 
UPDATE TCP_54_in SET category =1 where srcIP = '172.16.112.50' and destIP='196.37.75.158' and packetime between '1999-04-08 12:07:30' and '1999-04-08 12:07:31' and destPort in (8000) 
UPDATE TCP_54_in SET category =1 where srcIP = '172.16.112.50' and destIP='196.37.75.158' and packetime between '1999-04-08 12:08:00' and '1999-04-08 12:08:01' and destPort in (8000) 
UPDATE TCP_54_in SET category =1 where srcIP = '172.16.112.50' and destIP='196.37.75.158' and packetime between '1999-04-08 12:08:30' and '1999-04-08 12:08:31' and destPort in (8000) 
UPDATE TCP_54_in SET category =1 where srcIP = '172.16.112.50' and destIP='196.37.75.158' and packetime between '1999-04-08 12:09:00' and '1999-04-08 12:09:01' and destPort in (8000) 
UPDATE TCP_54_in SET category =1 where srcIP = '172.16.112.50' and destIP='196.37.75.158' and packetime between '1999-04-08 12:09:30' and '1999-04-08 12:09:31' and destPort in (8000) 
UPDATE TCP_54_in SET category =1 where srcIP = '172.16.112.50' and destIP='196.37.75.158' and packetime between '1999-04-08 12:10:00' and '1999-04-08 12:10:01' and destPort in (8000) 
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.112.50' and packetime between '1999-04-08 12:57:17' and '1999-04-08 12:59:34' and destPort in (20,21,23)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.112.50' and packetime between '1999-04-08 13:11:54' and '1999-04-08 13:37:27' and destPort in (20,21,23)
UPDATE TCP_54_in SET category =1 where srcIP = '209.74.60.168' and destIP='172.16.114.50' and packetime between '1999-04-08 14:58:29' and '1999-04-08 15:00:41' and destPort < 10000
UPDATE TCP_54_in SET category =1 where srcIP = '199.227.99.125' and destIP='172.16.114.50' and packetime between '1999-04-08 15:53:18' and '1999-04-08 16:08:19' and destPort in (23)
UPDATE TCP_54_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.100' and packetime between '1999-04-08 16:03:15' and '1999-04-08 16:03:22' and destPort in (20,21,23)
UPDATE TCP_54_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.100' and packetime between '1999-04-08 16:03:24' and '1999-04-08 16:10:06' and destPort in (20,21,23)
UPDATE TCP_54_in SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.100' and packetime between '1999-04-08 16:20:08' and '1999-04-08 16:25:11' and destPort in (20,21,23)
UPDATE TCP_54_in SET category =1 where srcIP = '172.16.117.103' and LEFT(destIP,11)='172.16.112.' and packetime between '1999-04-08 17:01:19' and '1999-04-08 17:02:21' and destPort in (21)
UPDATE TCP_54_in SET category =1 where srcIP in( '172.16.112.5','172.16.112.10','207.136.86.223') and destIP='172.16.112.1' and packetime between '1999-04-08 17:16:10' and '1999-04-08 17:16:11' --i src dest
UPDATE TCP_54_in SET category =1 where srcIP in( '172.16.112.5','172.16.112.10','207.136.86.223') and destIP='172.16.112.2' and packetime between '1999-04-08 17:16:20' and '1999-04-08 17:16:21' --i src dest
UPDATE TCP_54_in SET category =1 where srcIP in( '172.16.112.5','172.16.112.10','207.136.86.223') and destIP='172.16.112.3' and packetime between '1999-04-08 17:16:30' and '1999-04-08 17:16:31' --i src dest
UPDATE TCP_54_in SET category =1 where srcIP in( '172.16.112.5','172.16.112.10','207.136.86.223') and destIP='172.16.112.4' and packetime between '1999-04-08 17:16:40' and '1999-04-08 17:16:41' --i src dest
UPDATE TCP_54_in SET category =1 where srcIP in( '172.16.112.5','172.16.112.10','207.136.86.223') and destIP='172.16.112.5' and packetime between '1999-04-08 17:16:50' and '1999-04-08 17:16:51' --i src dest
UPDATE TCP_54_in SET category =1 where srcIP in( '172.16.112.5','172.16.112.10','207.136.86.223') and destIP='207.136.86.223' and packetime between '1999-04-08 17:16:50' and '1999-04-08 17:16:51' --i src dest
UPDATE TCP_54_in SET category =1 where srcIP in( '172.16.112.5','172.16.112.10','207.136.86.223') and destIP='172.16.112.6' and packetime between '1999-04-08 17:17:00' and '1999-04-08 17:17:01' --i src dest
UPDATE TCP_54_in SET category =1 where srcIP in( '172.16.112.5','172.16.112.10','207.136.86.223') and destIP='172.16.112.7' and packetime between '1999-04-08 17:17:10' and '1999-04-08 17:17:11' --i src dest
UPDATE TCP_54_in SET category =1 where srcIP in( '172.16.112.5','172.16.112.10','207.136.86.223') and destIP='172.16.112.8' and packetime between '1999-04-08 17:17:20' and '1999-04-08 17:17:21' --i src dest
UPDATE TCP_54_in SET category =1 where srcIP in( '172.16.112.5','172.16.112.10','207.136.86.223') and destIP='172.16.112.9' and packetime between '1999-04-08 17:17:30' and '1999-04-08 17:17:31' --i src dest
UPDATE TCP_54_in SET category =1 where srcIP in( '172.16.112.5','172.16.112.10','207.136.86.223') and destIP='172.16.112.10' and packetime between '1999-04-08 17:17:40' and '1999-04-08 17:17:41' --i src dest
UPDATE TCP_54_in SET category =1 where srcIP in( '172.16.112.5','172.16.112.10','207.136.86.223') and destIP='207.136.86.223' and packetime between '1999-04-08 17:17:40' and '1999-04-08 17:17:41' --i src dest
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:50:12' and '1999-04-08 17:50:13' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:50:17' and '1999-04-08 17:50:18' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:50:22' and '1999-04-08 17:50:23' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:50:28' and '1999-04-08 17:50:29' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:50:33' and '1999-04-08 17:50:34' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:50:38' and '1999-04-08 17:50:39' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:50:43' and '1999-04-08 17:50:44' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:50:48' and '1999-04-08 17:50:49' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:50:53' and '1999-04-08 17:50:54' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:50:58' and '1999-04-08 17:50:59' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:51:03' and '1999-04-08 17:51:04' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:51:08' and '1999-04-08 17:51:09' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:51:13' and '1999-04-08 17:51:14' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:51:18' and '1999-04-08 17:51:19' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:51:23' and '1999-04-08 17:51:24' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:51:28' and '1999-04-08 17:51:29' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:51:33' and '1999-04-08 17:51:34' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:51:39' and '1999-04-08 17:51:40' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:51:44' and '1999-04-08 17:51:45' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:51:49' and '1999-04-08 17:51:50' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:51:54' and '1999-04-08 17:51:55' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:51:59' and '1999-04-08 17:52:00' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:52:04' and '1999-04-08 17:52:05' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:52:09' and '1999-04-08 17:52:10' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:52:14' and '1999-04-08 17:52:15' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:52:19' and '1999-04-08 17:52:20' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:52:24' and '1999-04-08 17:52:25' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:52:29' and '1999-04-08 17:52:30' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:52:34' and '1999-04-08 17:52:35' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:52:39' and '1999-04-08 17:52:40' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:52:45' and '1999-04-08 17:52:46' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:52:50' and '1999-04-08 17:52:51' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:52:55' and '1999-04-08 17:52:56' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:53:00' and '1999-04-08 17:53:01' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:53:05' and '1999-04-08 17:53:06' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:53:10' and '1999-04-08 17:53:11' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:53:15' and '1999-04-08 17:53:16' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:53:20' and '1999-04-08 17:53:21' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:53:25' and '1999-04-08 17:53:26' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:53:30' and '1999-04-08 17:53:31' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:53:35' and '1999-04-08 17:53:36' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:53:40' and '1999-04-08 17:53:41' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:53:46' and '1999-04-08 17:53:47' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:53:51' and '1999-04-08 17:53:52' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:53:56' and '1999-04-08 17:53:57' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:54:01' and '1999-04-08 17:54:02' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:54:06' and '1999-04-08 17:54:07' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:54:11' and '1999-04-08 17:54:12' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:54:16' and '1999-04-08 17:54:17' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:54:21' and '1999-04-08 17:54:22' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:54:26' and '1999-04-08 17:54:27' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:54:31' and '1999-04-08 17:54:32' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:54:36' and '1999-04-08 17:54:37' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:54:41' and '1999-04-08 17:54:42' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:54:46' and '1999-04-08 17:54:47' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:54:52' and '1999-04-08 17:54:53' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:54:57' and '1999-04-08 17:54:58' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:55:02' and '1999-04-08 17:55:03' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:55:07' and '1999-04-08 17:55:08' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:55:12' and '1999-04-08 17:55:13' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:55:17' and '1999-04-08 17:55:18' and destPort in (161)
UPDATE TCP_54_in SET category =1 where srcIP = '206.48.44.18' and destIP='172.16.112.100' and packetime between '1999-04-08 18:31:00' and '1999-04-08 18:47:09'  and destPort in (20,21,23,80,139)
UPDATE TCP_54_in SET category =1 where srcIP = '206.48.44.18' and destIP='172.16.112.100' and packetime between '1999-04-08 18:47:10' and '1999-04-08 18:47:11' and destPort in (20,21,23,80,139)
UPDATE TCP_54_in SET category =1 where srcIP = '209.12.13.144' and destIP='172.16.112.20' and packetime between '1999-04-08 19:08:31' and '1999-04-08 19:08:32' and destPort in (53)
UPDATE TCP_54_in SET category =1 where srcIP = '209.30.70.14' and destIP='172.16.112.50' and packetime between '1999-04-08 19:41:14' and '1999-04-08 19:41:55' and destPort in (20,21)
UPDATE TCP_54_in SET category =1 where srcIP = '172.16.112.50' and destIP='209.30.70.14' and packetime between '1999-04-08 19:41:44' and '1999-04-08 19:41:45'
UPDATE TCP_54_in SET category =1 where srcIP = '207.136.86.223' and destIP in('172.16.112.10','172.16.112.20','172.16.112.50','172.16.112.100','172.16.112.149','172.16.112.194','172.16.112.207') and packetime between '1999-04-08 19:58:30' and '1999-04-08 23:59:59' and destPort in (23,25,79,80,110,111,143,6000)
UPDATE TCP_54_in SET category =1 where srcIP = '207.136.86.223' and destIP in('172.16.113.50','172.16.113.84','172.16.113.105','172.16.113.204') and packetime between '1999-04-08 19:58:30' and '1999-04-08 23:59:59'
and destPort in (23,25,79,80,110,111,143,6000)
--
UPDATE TCP_55_in SET category =1 where srcIP = '207.136.86.223' and destIP in ('172.16.114.50','172.16.114.148','172.16.114.168','172.16.114.169','172.16.114.207') and packetime between '1999-04-09 00:00:01' and '1999-04---09 02:18:01'
UPDATE TCP_55_in SET category =1 where srcIP = '172.16.113.50' and destIP='206.48.44.50' and packetime between '1999-04-09 08:01:28' and '1999-04-09 08:01:29' and destPort in (34904,49826,50460)
UPDATE TCP_55_in SET category =1 where srcIP = '172.16.113.50' and destIP='206.48.44.50' and packetime between '1999-04-09 08:01:39' and '1999-04-09 08:01:40' and destPort in (34904,49826,50460)
UPDATE TCP_55_in SET category =1 where srcIP = '172.16.113.50' and destIP='206.48.44.50' and packetime between '1999-04-09 08:01:56' and '1999-04-09 08:01:57' and destPort in (34904,49826,50460)
UPDATE TCP_55_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.113.50' and packetime between '1999-04-09 08:08:37' and '1999-04-09 08:09:56' and destPort in (6000)
UPDATE TCP_55_in SET category =1 where srcIP = '172.16.117.111' and destIP='172.16.112.100' and packetime between '1999-04-09 08:14:17' and '1999-04-09 08:30:02' and destPort in (80)
UPDATE TCP_55_in SET category =1 where srcIP = '172.16.112.98' and LEFT(destIP,11)='172.16.112.' and packetime between '1999-04-09 08:26:21' and '1999-04-09 08:44:14'
UPDATE TCP_55_in SET category =1 where srcIP = '206.47.98.151' and destIP='172.16.114.50' and packetime between '1999-04-09 08:44:16' and '1999-04-09 08:46:05' and destPort in (80)
UPDATE TCP_55_in SET category =1 where srcIP = '172.16.113.204' and destIP='172.16.112.100' and packetime between '1999-04-09 08:57:31' and '1999-04-09 08:57:32' and destPort in (25,53)
UPDATE TCP_55_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.112.207' and packetime between '1999-04-09 09:16:17' and '1999-04-09 09:21:49' and sourcePort in (20,21) and destPort in (23)
UPDATE TCP_55_in SET category =1 where srcIP = '153.10.8.174' and destIP='172.16.112.50' and packetime between '1999-04-09 09:31:11' and '1999-04-09 09:31:12' and destPort in (17,53,513) --i src
UPDATE TCP_55_in SET category =1 where srcIP = '153.10.8.174' and destIP='172.16.112.50' and packetime between '1999-04-09 09:34:31' and '1999-04-09 09:34:32' and destPort in (17,53,513) --i src
UPDATE TCP_55_in SET category =1 where srcIP = '153.10.8.174' and destIP='172.16.112.50' and packetime between '1999-04-09 09:37:51' and '1999-04-09 09:37:52' and destPort in (17,53,513) --i src
UPDATE TCP_55_in SET category =1 where srcIP = '172.16.118.50' and destIP='172.16.112.50' and packetime between '1999-04-09 10:08:13' and '1999-04-09 10:08:18' and destPort in (23)
UPDATE TCP_55_in SET category =1 where srcIP = '172.16.118.50' and destIP='172.16.112.50' and packetime between '1999-04-09 10:08:19' and '1999-04-09 10:08:24' and destPort in (23)
UPDATE TCP_55_in SET category =1 where srcIP = '172.16.118.50' and destIP='172.16.112.50' and packetime between '1999-04-09 10:08:25' and '1999-04-09 10:08:30' and destPort in (23)
UPDATE TCP_55_in SET category =1 where srcIP = '172.16.118.50' and destIP='172.16.112.50' and packetime between '1999-04-09 10:08:31' and '1999-04-09 10:08:36' and destPort in (23)
UPDATE TCP_55_in SET category =1 where srcIP = '172.16.118.50' and destIP='172.16.112.50' and packetime between '1999-04-09 10:08:37' and '1999-04-09 10:08:42' and destPort in (23)
UPDATE TCP_55_in SET category =1 where srcIP = '172.16.118.50' and destIP='172.16.112.50' and packetime between '1999-04-09 10:08:43' and '1999-04-09 10:08:48' and destPort in (23)
UPDATE TCP_55_in SET category =1 where srcIP = '172.16.118.50' and destIP='172.16.112.50' and packetime between '1999-04-09 10:08:49' and '1999-04-09 10:08:59' and destPort in (23)
UPDATE TCP_55_in SET category =1 where srcIP = '172.16.118.50' and destIP='172.16.112.50' and packetime between '1999-04-09 10:09:00' and '1999-04-09 10:09:05' and destPort in (23)
UPDATE TCP_55_in SET category =1 where destIP='172.16.112.100' and packetime between '1999-04-09 10:20:00' and '1999-04-09 10:25:00'
UPDATE TCP_55_in SET category =1 where destIP='172.16.114.50' and packetime between '1999-04-09 10:35:00' and '1999-04-09 10:40:00'
UPDATE TCP_55_in SET category =1 where srcIP = '172.16.112.100' and destIP='172.16.112.100' and packetime between '1999-04-09 10:45:00' and '1999-04-09 11:00:00' and destPort in (25)
UPDATE TCP_55_in SET category =1 where srcIP = '172.16.112.100' and destIP='172.16.112.100' and packetime between '1999-04-09 10:46:16' and '1999-04-09 10:48:53' and destPort in (25)
UPDATE TCP_55_in SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.112.100' and packetime between '1999-04-09 11:10:26' and '1999-04-09 11:10:31' and sourcePort in (80) and destPort in (25)
UPDATE TCP_55_in SET category =1 where srcIP = '206.186.80.111' and destIP='172.16.113.50' and packetime between '1999-04-09 11:52:10' and '1999-04-09 11:52:11' and destPort in (7,9,19,79)
UPDATE TCP_55_in SET category =1 where srcIP = '206.186.80.111' and destIP='172.16.113.50' and packetime between '1999-04-09 11:52:16' and '1999-04-09 11:52:17' and destPort in (7,9,19,79)
UPDATE TCP_55_in SET category =1 where srcIP = '206.186.80.111' and destIP='172.16.113.50' and packetime between '1999-04-09 11:54:02' and '1999-04-09 11:54:03' and destPort in (7,9,19,79)
UPDATE TCP_55_in SET category =1 where srcIP = '206.186.80.111' and destIP='172.16.113.50' and packetime between '1999-04-09 11:54:08' and '1999-04-09 11:54:09' and destPort in (7,9,19,79)
UPDATE TCP_55_in SET category =1 where srcIP = '206.186.80.111' and destIP='172.16.113.50' and packetime between '1999-04-09 11:55:55' and '1999-04-09 11:55:56' and destPort in (7,9,19,79)
UPDATE TCP_55_in SET category =1 where srcIP = '206.186.80.111' and destIP='172.16.113.50' and packetime between '1999-04-09 11:56:01' and '1999-04-09 11:56:02' and destPort in (7,9,19,79)
UPDATE TCP_55_in SET category =1 where srcIP = '206.186.80.111' and destIP='172.16.113.50' and packetime between '1999-04-09 11:57:47' and '1999-04-09 11:57:48' and destPort in (7,9,19,79)
UPDATE TCP_55_in SET category =1 where srcIP = '206.186.80.111' and destIP='172.16.113.50' and packetime between '1999-04-09 11:57:53' and '1999-04-09 11:57:54' and destPort in (7,9,19,79)
UPDATE TCP_55_in SET category =1 where srcIP = '206.186.80.111' and destIP='172.16.112.194' and packetime between '1999-04-09 12:34:15' and '1999-04-09 12:35:17'  and destPort in (23)
UPDATE TCP_55_in SET category =1 where srcIP = '209.1.12.46' and destIP='172.16.112.100' and packetime between '1999-04-09 12:44:38' and '1999-04-09 12:58:57' and destPort in (23,80)
UPDATE TCP_55_in SET category =1 where srcIP = '209.1.12.46' and destIP='172.16.112.100' and packetime between '1999-04-09 12:51:12' and '1999-04-09 13:06:44' and destPort in (23,80)
UPDATE TCP_55_in SET category =1 where srcIP = '135.13.216.191' and destIP='172.16.112.100' and packetime between '1999-04-09 12:58:11' and '1999-04-09 13:01:11' and destPort in (23)
UPDATE TCP_55_in SET category =1 where srcIP = '209.1.12.46' and destIP='172.16.112.100' and packetime between '1999-04-09 12:58:30' and '1999-04-09 13:13:33' and destPort in (23,80)
UPDATE TCP_55_in SET category =1 where srcIP = '209.1.12.46' and destIP='172.16.112.100' and packetime between '1999-04-09 12:59:06' and '1999-04-09 13:02:20' and destPort in (23,80)
UPDATE TCP_55_in SET category =1 where srcIP = '135.13.216.191' and destIP='172.16.112.100' and packetime between '1999-04-09 13:01:12' and '1999-04-09 13:04:42' and destPort in (23)
UPDATE TCP_55_in SET category =1 where srcIP = '135.13.216.191' and destIP='172.16.112.100' and packetime between '1999-04-09 13:04:43' and '1999-04-09 13:08:14' and destPort in (23)
UPDATE TCP_55_in SET category =1 where srcIP = '172.5.4.66' and destIP='172.16.112.50' and packetime between '1999-04-09 14:06:15' and '1999-04-09 14:21:16' and destPort in (514)
UPDATE TCP_55_in SET category =1 where srcIP = '206.48.44.50' and destIP='172.16.112.50' and packetime between '1999-04-09 14:17:28' and '1999-04-09 14:17:53' and destPort in (20,21,23)
UPDATE TCP_55_in SET category =1 where srcIP = '172.16.112.50' and destIP='206.48.44.50' and packetime between '1999-04-09 14:17:42' and '1999-04-09 14:17:51' and destPort in (25)
UPDATE TCP_55_in SET category =1 where srcIP = '206.48.44.50' and destIP='172.16.112.50' and packetime between '1999-04-09 14:21:17' and '1999-04-09 14:21:46' and destPort in (20,21,23)
UPDATE TCP_55_in SET category =1 where srcIP = ' 172.16.113.50' and destIP='172.16.113.50' and packetime between '1999-04-09 14:32:27' and '1999-04-09 14:47:28' and destPort in (25)
UPDATE TCP_55_in SET category =1 where srcIP = '172.5.4.65' and destIP='172.16.112.50' and packetime between '1999-04-09 14:56:30' and '1999-04-09 15:11:31' and destPort in (514)
UPDATE TCP_55_in SET category =1 where srcIP = '152.204.242.193' and destIP='172.16.114.50' and packetime between '1999-04-09 17:27:15' and '1999-04-09 17:27:26' and destPort in (25)
UPDATE TCP_55_in SET category =1 where srcIP = '202.72.1.77' and destIP='172.16.113.105' and packetime between '1999-04-09 17:47:15' and '1999-04-09 17:47:45' and destPort in (20,21,23)
UPDATE TCP_55_in SET category =1 where srcIP = '202.72.1.77' and destIP='172.16.113.105' and packetime between '1999-04-09 17:56:45' and '1999-04-09 18:24:55' and destPort in (20,21,23)
UPDATE TCP_55_in SET category =1 where srcIP = '11.21.31.41' and destIP='172.16.113.50' and packetime between '1999-04-09 18:30:04' and '1999-04-09 18:30:13' and destPort in (21)
UPDATE TCP_55_in SET category =1 where srcIP = '172.16.112.194' and destIP='172.16.114.50' and packetime between '1999-04-09 18:47:14' and '1999-04-09 19:23:03'  and destPort in (23)
UPDATE TCP_55_in SET category =1 where srcIP = '206.47.98.151' and destIP='172.16.112.50' and packetime between '1999-04-09 18:52:09' and '1999-04-09 18:52:50'  and destPort in (20,21)
UPDATE TCP_55_in SET category =1 where srcIP = '207.136.86.223' and destIP in ('172.16.114.50','172.16.114.148','172.16.114.168','172.16.114.169','172.16.114.207') and packetime between '1999-04-09 19:58:30' and '1999-04-09 23:59:59'
UPDATE TCP_55_in SET category =1 where srcIP = '207.136.86.223' and destIP in ('172.16.115.5','172.16.115.87','172.16.115.234') and packetime between '1999-04-09 19:58:30' and '1999-04-09 23:59:59'
UPDATE TCP_55_in SET category =1 where srcIP = '207.136.86.223' and destIP in ('172.16.116.44','172.16.116.194','172.16.116.201') and packetime between '1999-04-09 19:58:30' and '1999-04-09 23:59:59'
UPDATE TCP_55_in SET category =1 where srcIP = '207.136.86.223' and destIP in ('172.16.117.52','172.16.117.103','172.16.117.111','172.16.117.132') and packetime between '1999-04-09 19:58:30' and '1999-04-09 23:59:59'
UPDATE TCP_55_in SET category =1 where srcIP = '207.136.86.223' and destIP in ('172.16.118.10','172.16.118.20','172.16.118.30','172.16.118.40','172.16.118.50','172.16.118.60','172.16.118.70','172.16.118.80','172.16.118.90','172.16.118.100') and packetime between '1999-04-09 19:58:30' and '1999-04-09 23:59:59'
UPDATE TCP_55_in SET category =1 where destIP='172.16.112.50' and packetime between '1999-04-09 20:05:30' and '1999-04-09 20:15:30'
UPDATE TCP_55_in SET category =1 where srcIP = '205.160.208.190' and destIP='172.16.0.1' and packetime between '1999-04-09 20:20:20' and '1999-04-09 20:20:21' and destPort in (80)
UPDATE TCP_55_in SET category =1 where srcIP = '205.160.208.190' and destIP='172.16.0.1' and packetime between '1999-04-09 20:23:21' and '1999-04-09 20:23:22' and destPort in (80)
UPDATE TCP_55_in SET category =1 where srcIP = '205.160.208.190' and destIP='172.16.0.1' and packetime between '1999-04-09 20:26:22' and '1999-04-09 20:26:23' and destPort in (80)
UPDATE TCP_55_in SET category =1 where srcIP = '205.160.208.190' and destIP='172.16.0.1' and packetime between '1999-04-09 20:29:23' and '1999-04-09 20:29:24' and destPort in (80)
UPDATE TCP_55_in SET category =1 where srcIP = '205.160.208.190' and destIP='172.16.0.1' and packetime between '1999-04-09 20:32:24' and '1999-04-09 20:32:25' and destPort in (80)
UPDATE TCP_55_in SET category =1 where srcIP = '205.160.208.190' and destIP='172.16.0.1' and packetime between '1999-04-09 20:35:25' and '1999-04-09 20:35:26' and destPort in (80)
UPDATE TCP_55_in SET category =1 where srcIP = '205.160.208.190' and destIP='172.16.0.1' and packetime between '1999-04-09 20:38:26' and '1999-04-09 20:38:27' and destPort in (80)
UPDATE TCP_55_in SET category =1 where srcIP = '204.71.51.16' and destIP='172.16.112.100' and packetime between '1999-04-09 20:49:17' and '1999-04-09 20:49:31' and destPort in (20,21,23)
UPDATE TCP_55_in SET category =1 where srcIP = '204.71.51.16' and destIP='172.16.112.100' and packetime between '1999-04-09 20:49:33' and '1999-04-09 21:07:55' and destPort in (20,21,23)
UPDATE TCP_55_in SET category =1 where srcIP = '204.71.51.16' and destIP='172.16.112.100' and packetime between '1999-04-09 21:22:58' and '1999-04-09 21:33:04' and destPort in (20,21,23)

--
UPDATE TCP_51_out SET category =1 where srcIP = '202.77.162.213' and destIP='172.16.112.50' and packetime between '1999-04-05 08:39:52' and '1999-04-05 08:40:02' -- i
UPDATE TCP_51_out SET category =1 where srcIP = '172.16.118.10' and destIP='192.168.1.1' and packetime between '1999-04-05 08:43:17' and '1999-04-05 08:43:18' and destPort in (79,80,143)
UPDATE TCP_51_out SET category =1 where srcIP = '172.16.118.10' and destIP='192.168.1.1' and packetime between '1999-04-05 08:45:13' and '1999-04-05 08:45:14' and destPort in (79,80,143)
UPDATE TCP_51_out SET category =1 where srcIP = '172.16.118.10' and destIP='192.168.1.1' and packetime between '1999-04-05 08:47:09' and '1999-04-05 08:47:10' and destPort in (79,80,143)
UPDATE TCP_51_out SET category =1 where srcIP = '202.77.162.213' and destIP='172.16.114.50' and packetime between '1999-04-05 08:48:33' and '1999-04-05 08:48:38' --i
UPDATE TCP_51_out SET category =1 where srcIP = '207.75.239.115' and destIP='172.16.112.50' and packetime between '1999-04-05 08:59:16' and '1999-04-05 08:59:57' and destPort in (20,21)
UPDATE TCP_51_out SET category =1 where destIP='172.16.112.50' and packetime between '1999-04-05 09:33:00' and '1999-04-05 09:35:00' --i
UPDATE TCP_51_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:43:11' and '1999-04-05 09:43:19' and destPort < 101
UPDATE TCP_51_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:43:24' and '1999-04-05 09:43:25' and destPort < 101
UPDATE TCP_51_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:43:31' and '1999-04-05 09:43:34' and destPort < 101
UPDATE TCP_51_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:43:35' and '1999-04-05 09:43:38' and destPort < 101
UPDATE TCP_51_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:43:43' and '1999-04-05 09:43:44' and destPort < 101
UPDATE TCP_51_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:43:50' and '1999-04-05 09:43:52' and destPort < 101
UPDATE TCP_51_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:43:57' and '1999-04-05 09:43:58' and destPort < 101
UPDATE TCP_51_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:44:04' and '1999-04-05 09:44:08' and destPort < 101
UPDATE TCP_51_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:44:09' and '1999-04-05 09:44:13' and destPort < 101
UPDATE TCP_51_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:44:18' and '1999-04-05 09:44:19' and destPort < 101
UPDATE TCP_51_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:44:25' and '1999-04-05 09:44:29' and destPort < 101
UPDATE TCP_51_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:44:34' and '1999-04-05 09:44:35' and destPort < 101
UPDATE TCP_51_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:44:41' and '1999-04-05 09:44:43' and destPort < 101
UPDATE TCP_51_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:44:44' and '1999-04-05 09:44:49' and destPort < 101
UPDATE TCP_51_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:44:54' and '1999-04-05 09:44:55' and destPort < 101
UPDATE TCP_51_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:45:01' and '1999-04-05 09:45:04' and destPort < 101
UPDATE TCP_51_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:45:05' and '1999-04-05 09:45:07' and destPort < 101
UPDATE TCP_51_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:45:12' and '1999-04-05 09:45:13' and destPort < 101
UPDATE TCP_51_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:45:19' and '1999-04-05 09:45:28' and destPort < 101
UPDATE TCP_51_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:45:29' and '1999-04-05 09:45:39' and destPort < 101
UPDATE TCP_51_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:45:44' and '1999-04-05 09:45:45' and destPort < 101
UPDATE TCP_51_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:45:52' and '1999-04-05 09:46:02' and destPort < 101
UPDATE TCP_51_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:46:03' and '1999-04-05 09:46:14' and destPort < 101
UPDATE TCP_51_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:46:15' and '1999-04-05 09:46:21' and destPort < 101
UPDATE TCP_51_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:46:26' and '1999-04-05 09:46:27' and destPort < 101
UPDATE TCP_51_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:46:33' and '1999-04-05 09:46:34' and destPort < 101
UPDATE TCP_51_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:46:35' and '1999-04-05 09:46:36' and destPort < 101
UPDATE TCP_51_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:46:37' and '1999-04-05 09:46:48' and destPort < 101
UPDATE TCP_51_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.50' and packetime between '1999-04-05 09:46:53' and '1999-04-05 09:46:54' and destPort < 101
UPDATE TCP_51_out SET category =1 where srcIP = '202.77.162.213' and destIP='172.16.114.50' and sourcePort='1389' and destPort='80' and packetime between '1999-04-05 10:29:22' and '1999-04-05 10:46:59' 
UPDATE TCP_51_out SET category =1 where srcIP = '192.5.41.239' and destIP='172.16.118.80' and sourcePort='37' and destPort='23' and packetime between '1999-04-05 10:58:14' and '1999-04-05 11:00:00'
UPDATE TCP_51_out SET category =1 where srcIP = '192.5.41.239' and destIP='172.16.118.80' and packetime between '1999-04-05 11:00:01' and '1999-04-05 11:01:34' 
UPDATE TCP_51_out SET category =1 where srcIP = '172.16.115.234' and destIP='172.16.112.100' and destPort='139' and packetime between '1999-04-05 11:45:27' and '1999-04-05 12:02:00'
UPDATE TCP_51_out SET category =1 where srcIP = '172.16.114.207' and destIP='172.16.113.50' and destPort='23' and packetime between '1999-04-05 12:03:14' and '1999-04-05 12:14:29'
UPDATE TCP_51_out SET category =1 where srcIP = '135.13.216.191' and destIP='172.16.112.50' and destPort='23' and packetime between '1999-04-05 12:11:18' and '1999-04-05 12:23:46'
UPDATE TCP_51_out SET category =1 where srcIP = '23.234.78.52' and destIP='172.16.114.50' --i
UPDATE TCP_51_out SET category =1 where srcIP = '152.169.215.104' and destIP='172.16.112.100' and packetime between '1999-04-05 13:30:14' and '1999-04-05 13:30:31'
UPDATE TCP_51_out SET category =1 where srcIP = '152.169.215.104' and destIP='172.16.112.100' and packetime between '1999-04-05 13:33:52' and '1999-04-05 13:44:51'
UPDATE TCP_51_out SET category =1 where srcIP = '152.169.215.104' and sourcePort in(2275,2276,2277,2358,2639,2750,2759,2943,3380,3483,3662,3906) and destIP='172.16.114.50' and packetime between '1999-04-05 14:05:43' and '1999-04-05 14:15:47' and destPort in (80)
UPDATE TCP_51_out SET category =1 where srcIP = '152.169.215.104' and destIP='206.48.44.50' and packetime between '1999-04-05 14:16:51' and '1999-04-05 14:16:52' and sourcePort in(2275,2276,2277,2358,2639,2750,2759,2943,3380,3483,3662,3906) 
UPDATE TCP_51_out SET category =1 where srcIP = '10.11.22.33' and destIP='172.16.113.50' and packetime between '1999-04-05 14:22:30' and '1999-04-05 14:22:31' --i
UPDATE TCP_51_out SET category =1 where srcIP = '172.16.117.103' and destIP='172.16.114.50' and packetime between '1999-04-05 14:46:19' and '1999-04-05 14:46:29' and destPort in (143)
UPDATE TCP_51_out SET category =1 where srcIP in( '128.223.199.68','172.16.113.50','204.71.51.16','204.233.47.21','207.114.237.57','209.1.12.46') and destIP='172.16.113.1' and packetime between '1999-04-05 15:00:16' and '1999-04-05 15:00:17' --i
UPDATE TCP_51_out SET category =1 where srcIP in( '128.223.199.68','172.16.113.50','204.71.51.16','204.233.47.21','207.114.237.57','209.1.12.46') and destIP='172.16.113.3' and packetime between '1999-04-05 15:04:06' and '1999-04-05 15:04:07' --i
UPDATE TCP_51_out SET category =1 where srcIP in( '128.223.199.68','172.16.113.50','204.71.51.16','204.233.47.21','207.114.237.57','209.1.12.46') and destIP='172.16.113.5' and packetime between '1999-04-05 15:07:56' and '1999-04-05 15:07:57' --i
UPDATE TCP_51_out SET category =1 where srcIP in( '128.223.199.68','172.16.113.50','204.71.51.16','204.233.47.21','207.114.237.57','209.1.12.46') and destIP='172.16.113.4' and packetime between '1999-04-05 15:11:46' and '1999-04-05 15:11:47' --i
UPDATE TCP_51_out SET category =1 where srcIP in( '128.223.199.68','172.16.113.50','204.71.51.16','204.233.47.21','207.114.237.57','209.1.12.46') and destIP='172.16.113.50' and packetime between '1999-04-05 15:15:36' and '1999-04-05 15:15:37' --i
UPDATE TCP_51_out SET category =1 where srcIP in( '128.223.199.68','172.16.113.50','204.71.51.16','204.233.47.21','207.114.237.57','209.1.12.46') and destIP='204.233.47.21' and packetime between '1999-04-05 15:15:36' and '1999-04-05 15:15:37' --i
UPDATE TCP_51_out SET category =1 where srcIP = '172.16.118.10' and destIP='172.16.114.50' and packetime between '1999-04-05 16:32:17' and '1999-04-05 16:32:27' and destPort in (23)
UPDATE TCP_51_out SET category =1 where srcIP = '172.16.118.10' and destIP='172.16.114.50' and packetime between '1999-04-05 16:32:28' and '1999-04-05 16:32:59' and destPort in (23)
UPDATE TCP_51_out SET category =1 where srcIP = '172.16.118.10' and destIP='172.16.114.50' and packetime between '1999-04-05 16:33:00' and '1999-04-05 16:33:22' and destPort in (23)
UPDATE TCP_51_out SET category =1 where srcIP = '172.16.118.10' and destIP='172.16.114.50' and packetime between '1999-04-05 16:33:23' and '1999-04-05 16:42:03' and destPort in (23)
UPDATE TCP_51_out SET category =1 where srcIP = '172.16.118.10' and destIP='172.16.114.50' and packetime between '1999-04-05 16:42:04' and '1999-04-05 16:46:09' and destPort in (23)
UPDATE TCP_51_out SET category =1 where srcIP = '172.16.118.10' and destIP='172.16.114.50' and packetime between '1999-04-05 16:46:10' and '1999-04-05 16:48:52' and destPort in (23)
UPDATE TCP_51_out SET category =1 where srcIP = '172.5.3.5' and destIP='172.16.112.50' and packetime between '1999-04-05 17:19:10' and '1999-04-05 17:34:11' and destPort in (514)
UPDATE TCP_51_out SET category =1 where srcIP = '10.20.30.40' and destIP='172.16.112.50' and packetime between '1999-04-05 18:04:04' and '1999-04-05 18:10:55' and destPort < 1025
UPDATE TCP_51_out SET category =1 where srcIP = '202.72.1.77' and destIP='172.16.112.100' and packetime between '1999-04-05 18:36:11' and '1999-04-05 18:51:18' and destPort in (80)
UPDATE TCP_51_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.20' and packetime between '1999-04-05 18:57:21' and '1999-04-05 18:57:22' and destPort in (53)
UPDATE TCP_51_out SET category =1 where srcIP = '206.48.44.18' and destIP='172.16.115.234' and packetime between '1999-04-05 19:48:01' and '1999-04-05 20:04:42' and destPort in (139)
UPDATE TCP_51_out SET category =1 where srcIP = '172.16.112.50' and LEFT(destIP,11)='172.16.113.' and packetime between '1999-04-05 20:00:27' and '1999-04-05 20:15:27' and destPort in (7)
UPDATE TCP_51_out SET category =1 where srcIP = '135.13.216.191' and destIP='172.16.112.50' and packetime between '1999-04-05 20:17:12' and '1999-04-05 20:20:15' and destPort in (23)
UPDATE TCP_51_out SET category =1 where srcIP = '172.16.118.70' and destIP='172.16.114.50' and packetime between '1999-04-05 20:46:13' and '1999-04-05 20:47:42' and sourcePort in (20,21,25) and destPort in (23,113)
--
UPDATE TCP_52_out SET category =1 where srcIP = '135.8.60.182' and destIP='172.16.112.50' and packetime between '1999-04-06 08:11:15' and '1999-04-06 08:11:25' and destPort in (23)
UPDATE TCP_52_out SET category =1 where srcIP = '135.8.60.182' and destIP='172.16.112.50' and packetime between '1999-04-06 08:11:27' and '1999-04-06 08:22:05' and destPort in (23)
UPDATE TCP_52_out SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.114.50' and packetime between '1999-04-06 08:32:14' and '1999-04-06 08:47:15' and destPort in (23)
UPDATE TCP_52_out SET category =1 where srcIP = '172.16.113.204' and destIP='172.16.112.100' and packetime between '1999-04-06 08:53:17' and '1999-04-06 08:53:24' and destPort in (20,21,23)
UPDATE TCP_52_out SET category =1 where srcIP = '172.16.113.204' and destIP='172.16.112.100' and packetime between '1999-04-06 08:53:26' and '1999-04-06 09:10:42' and destPort in (20,21,23)
UPDATE TCP_52_out SET category =1 where srcIP = '194.7.248.153' and destIP='172.16.112.50' and packetime between '1999-04-06 09:19:01' and '1999-04-06 09:20:13'and destPort in (6000)
UPDATE TCP_52_out SET category =1 where srcIP = '172.16.113.204' and destIP='172.16.112.100' and packetime between '1999-04-06 09:33:15' and '1999-04-06 09:42:55' and destPort in (20,21,23)
UPDATE TCP_52_out SET category =1 where srcIP = '192.182.91.233' and destIP='172.16.112.50' and packetime between '1999-04-06 09:45:13' and '1999-04-06 09:48:16' and destPort in (23)
UPDATE TCP_52_out SET category =1 where srcIP = '152.169.215.104' and destIP='172.16.112.194' and packetime between '1999-04-06 10:07:18' and '1999-04-06 10:07:54'  and destPort in (20,21,23)
UPDATE TCP_52_out SET category =1 where srcIP = '172.16.114.207' and destIP='172.16.112.50' and packetime between '1999-04-06 10:19:16' and '1999-04-06 10:19:27'  and destPort in (20,21,513)
UPDATE TCP_52_out SET category =1 where srcIP = '172.16.114.207' and destIP='172.16.112.50' and packetime between '1999-04-06 10:32:48' and '1999-04-06 10:33:20' and destPort in (20,21,513)
UPDATE TCP_52_out SET category =1 where srcIP = '152.169.215.104' and destIP='172.16.112.194' and packetime between '1999-04-06 10:36:16' and '1999-04-06 10:48:01' and destPort in (20,21,513)
UPDATE TCP_52_out SET category =1 where srcIP = '199.227.99.125' and destIP='172.16.112.50' and packetime between '1999-04-06 11:20:09' and '1999-04-06 11:43:45' and sourcePort in (80,6000) and destPort in (23)
UPDATE TCP_52_out SET category =1 where srcIP = '206.48.44.50' and destIP='172.16.114.50' and packetime between '1999-04-06 11:31:21' and '1999-04-06 11:51:59' and sourcePort in (2222,2223,2284) and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '172.16.114.50' and destIP='206.48.44.50' and packetime between '1999-04-06 11:37:43' and '1999-04-06 11:37:44' and sourcePort in (2222,2223,2284) and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '10.20.30.40' and destIP='172.16.114.50' and packetime between '1999-04-06 11:38:04' and '1999-04-06 11:51:45' and destPort < 1025
UPDATE TCP_52_out SET category =1 where srcIP = '172.16.114.50' and destIP='206.48.44.50' and packetime between '1999-04-06 11:42:40' and '1999-04-06 11:42:41' and sourcePort in (2222,2223,2284) and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '172.16.114.50' and destIP='206.48.44.50' and packetime between '1999-04-06 11:47:03' and '1999-04-06 11:47:04' and sourcePort in (2222,2223,2284) and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '172.16.112.50' and destIP='196.37.75.158' and packetime between '1999-04-06 12:06:32' and '1999-04-06 12:10:02' and destPort in (8000)
UPDATE TCP_52_out SET category =1 where srcIP = '152.169.215.104' and destIP='172.16.112.50' and packetime between '1999-04-06 12:55:14' and '1999-04-06 13:11:46' and sourcePort in (20,21,25) and destPort in (23)
UPDATE TCP_52_out SET category =1 where srcIP = '199.227.99.125' and destIP='172.16.112.50' and packetime between '1999-04-06 12:59:00' and '1999-04-06 13:01:00'  and sourcePort in (80,6000) and destPort in (23)
UPDATE TCP_52_out SET category =1 where srcIP = '166.102.114.43' and destIP='172.16.113.50' and packetime between '1999-04-06 13:06:00' and '1999-04-06 13:06:30'
UPDATE TCP_52_out SET category =1 where srcIP = '194.7.248.153' and destIP='172.16.112.100' and packetime between '1999-04-06 13:28:11' and '1999-04-06 13:50:38' and destPort in (23,80)
UPDATE TCP_52_out SET category =1 where srcIP = '194.7.248.153' and destIP='172.16.112.100' and packetime between '1999-04-06 13:50:03' and '1999-04-06 14:05:08' and destPort in (23,80)
UPDATE TCP_52_out SET category =1 where srcIP = '194.7.248.153' and destIP='172.16.112.100' and packetime between '1999-04-06 13:58:10' and '1999-04-06 14:10:30' and destPort in (23,80)
UPDATE TCP_52_out SET category =1 where srcIP = '172.3.45.1' and destIP='172.16.112.50' and packetime between '1999-04-06 14:13:56' and '1999-04-06 14:13:57' and destPort in (514)
UPDATE TCP_52_out SET category =1 where srcIP = '207.103.80.104' and destIP='172.16.114.207' and packetime between '1999-04-06 14:24:17' and '1999-04-06 14:39:04' and destPort in (23)
UPDATE TCP_52_out SET category =1 where srcIP = '199.174.194.16' and destIP='172.16.112.100' and packetime between '1999-04-06 14:26:26' and '1999-04-06 14:26:37' and sourcePort in (137) and destPort in (25,80)--i
UPDATE TCP_52_out SET category =1 where srcIP = '199.174.194.16' and destIP='172.16.112.100' and packetime between '1999-04-06 14:34:11' and '1999-04-06 14:34:12' and sourcePort in (137) and destPort in (25,80)--i
UPDATE TCP_52_out SET category =1 where srcIP = '199.174.194.16' and destIP='172.16.112.100' and packetime between '1999-04-06 14:34:19' and '1999-04-06 14:34:20' and sourcePort in (137) and destPort in (25,80)--i
UPDATE TCP_52_out SET category =1 where srcIP = '199.174.194.16' and destIP='172.16.112.100' and packetime between '1999-04-06 14:34:41' and '1999-04-06 14:34:42' and sourcePort in (137) and destPort in (25,80)--i
UPDATE TCP_52_out SET category =1 where srcIP = '199.174.194.16' and destIP='172.16.112.100' and packetime between '1999-04-06 14:34:48' and '1999-04-06 14:34:49' and sourcePort in (137) and destPort in (25,80)--i
UPDATE TCP_52_out SET category =1 where srcIP = '199.174.194.16' and destIP='172.16.112.100' and packetime between '1999-04-06 14:36:19' and '1999-04-06 14:36:20' and sourcePort in (137) and destPort in (25,80)--i
UPDATE TCP_52_out SET category =1 where srcIP = '199.174.194.16' and destIP='172.16.112.100' and packetime between '1999-04-06 14:36:39' and '1999-04-06 14:36:40' and sourcePort in (137) and destPort in (25,80)--i
UPDATE TCP_52_out SET category =1 where srcIP = '199.174.194.16' and destIP='172.16.112.100' and packetime between '1999-04-06 14:36:47' and '1999-04-06 14:36:48' and sourcePort in (137) and destPort in (25,80)--i
UPDATE TCP_52_out SET category =1 where srcIP = '199.174.194.16' and destIP='172.16.112.100' and packetime between '1999-04-06 14:38:25' and '1999-04-06 14:38:26' and sourcePort in (137) and destPort in (25,80)--i
UPDATE TCP_52_out SET category =1 where srcIP = '199.174.194.16' and destIP='172.16.112.100' and packetime between '1999-04-06 14:38:34' and '1999-04-06 14:39:18' and sourcePort in (137) and destPort in (25,80)--i
UPDATE TCP_52_out SET category =1 where srcIP = '196.38.75.158' and destIP='172.16.112.50' and packetime between '1999-04-06 16:24:15' and '1999-04-06 16:24:48' and destPort in (20,21,23)
UPDATE TCP_52_out SET category =1 where srcIP = '196.38.75.158' and destIP='172.16.112.50' and packetime between '1999-04-06 16:40:15' and '1999-04-06 17:20:39' and destPort in (20,21,23)
UPDATE TCP_52_out SET category =1 where srcIP = '196.38.75.158' and destIP='172.16.113.50' and packetime between '1999-04-06 16:54:20' and '1999-04-06 16:54:21' and destPort in (20,21,23)
UPDATE TCP_52_out SET category =1 where srcIP = '196.38.75.158' and destIP='172.16.113.50' and packetime between '1999-04-06 16:54:22' and '1999-04-06 16:54:23' and destPort in (20,21,23)
UPDATE TCP_52_out SET category =1 where srcIP = '196.38.75.158' and destIP='172.16.113.50' and packetime between '1999-04-06 16:54:24' and '1999-04-06 16:54:25' and destPort in (20,21,23)
UPDATE TCP_52_out SET category =1 where srcIP = '196.38.75.158' and destIP='172.16.113.50' and packetime between '1999-04-06 16:54:45' and '1999-04-06 16:54:46' and destPort in (20,21,23)
UPDATE TCP_52_out SET category =1 where srcIP = '196.38.75.158' and destIP='172.16.113.50' and packetime between '1999-04-06 16:54:47' and '1999-04-06 16:54:48' and destPort in (20,21,23)
UPDATE TCP_52_out SET category =1 where srcIP = '196.38.75.158' and destIP='172.16.113.50' and packetime between '1999-04-06 16:54:49' and '1999-04-06 16:54:50' and destPort in (20,21,23)
UPDATE TCP_52_out SET category =1 where srcIP = '196.38.75.158' and destIP='172.16.113.50' and packetime between '1999-04-06 16:55:10' and '1999-04-06 16:55:11' and destPort in (20,21,23)
UPDATE TCP_52_out SET category =1 where srcIP = '196.38.75.158' and destIP='172.16.112.50' and packetime between '1999-04-06 17:22:15' and '1999-04-06 17:24:15' and destPort in (20,21,23)
UPDATE TCP_52_out SET category =1 where srcIP = '10.20.30.40' and destIP='192.168.1.1' and packetime between '1999-04-06 18:16:05' and '1999-04-06 18:19:31' and destPort<1025
UPDATE TCP_52_out SET category =1 where srcIP = '172.16.115.234' and destIP='172.16.112.100' and packetime between '1999-04-06 20:57:03' and '1999-04-06 21:13:36' and destPort in (139)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.148' and packetime between '1999-04-06 21:15:54' and '1999-04-06 21:15:57' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.148' and packetime between '1999-04-06 21:16:00' and '1999-04-06 21:16:03' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.148' and packetime between '1999-04-06 21:16:06' and '1999-04-06 21:16:09' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.148' and packetime between '1999-04-06 21:16:12' and '1999-04-06 21:16:15' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.148' and packetime between '1999-04-06 21:16:18' and '1999-04-06 21:16:21' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.100' and packetime between '1999-04-06 21:16:24' and '1999-04-06 21:16:27' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.100' and packetime between '1999-04-06 21:16:30' and '1999-04-06 21:16:33' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.100' and packetime between '1999-04-06 21:16:36' and '1999-04-06 21:16:39' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.100' and packetime between '1999-04-06 21:16:42' and '1999-04-06 21:16:45' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.100' and packetime between '1999-04-06 21:16:48' and '1999-04-06 21:16:51' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.10' and packetime between '1999-04-06 21:16:54' and '1999-04-06 21:16:57' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.10' and packetime between '1999-04-06 21:17:00' and '1999-04-06 21:17:03' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.10' and packetime between '1999-04-06 21:17:06' and '1999-04-06 21:17:09' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.10' and packetime between '1999-04-06 21:17:12' and '1999-04-06 21:17:15' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.10' and packetime between '1999-04-06 21:17:18' and '1999-04-06 21:17:21' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.20' and packetime between '1999-04-06 21:17:24' and '1999-04-06 21:17:27' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.20' and packetime between '1999-04-06 21:17:30' and '1999-04-06 21:17:33' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.20' and packetime between '1999-04-06 21:17:36' and '1999-04-06 21:17:39' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.20' and packetime between '1999-04-06 21:17:42' and '1999-04-06 21:17:45' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.20' and packetime between '1999-04-06 21:17:48' and '1999-04-06 21:17:51' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.30' and packetime between '1999-04-06 21:17:54' and '1999-04-06 21:17:57' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.30' and packetime between '1999-04-06 21:18:00' and '1999-04-06 21:18:03' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.30' and packetime between '1999-04-06 21:18:06' and '1999-04-06 21:18:09' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.30' and packetime between '1999-04-06 21:18:12' and '1999-04-06 21:18:15' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.30' and packetime between '1999-04-06 21:18:18' and '1999-04-06 21:18:21' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.40' and packetime between '1999-04-06 21:18:24' and '1999-04-06 21:18:27' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.40' and packetime between '1999-04-06 21:18:30' and '1999-04-06 21:18:33' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.40' and packetime between '1999-04-06 21:18:36' and '1999-04-06 21:18:39' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.40' and packetime between '1999-04-06 21:18:42' and '1999-04-06 21:18:45' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.40' and packetime between '1999-04-06 21:18:48' and '1999-04-06 21:18:51' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.50' and packetime between '1999-04-06 21:18:54' and '1999-04-06 21:18:57' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.50' and packetime between '1999-04-06 21:19:00' and '1999-04-06 21:19:03' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.50' and packetime between '1999-04-06 21:19:06' and '1999-04-06 21:19:09' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.50' and packetime between '1999-04-06 21:19:12' and '1999-04-06 21:19:15' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.50' and packetime between '1999-04-06 21:19:18' and '1999-04-06 21:19:21' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.60' and packetime between '1999-04-06 21:19:24' and '1999-04-06 21:19:27' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.60' and packetime between '1999-04-06 21:19:30' and '1999-04-06 21:19:33' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.60' and packetime between '1999-04-06 21:19:36' and '1999-04-06 21:19:39' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.60' and packetime between '1999-04-06 21:19:42' and '1999-04-06 21:19:45' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.60' and packetime between '1999-04-06 21:19:48' and '1999-04-06 21:19:51' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.70' and packetime between '1999-04-06 21:19:55' and '1999-04-06 21:19:58' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.70' and packetime between '1999-04-06 21:20:01' and '1999-04-06 21:20:04' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.70' and packetime between '1999-04-06 21:20:07' and '1999-04-06 21:20:10' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.70' and packetime between '1999-04-06 21:20:13' and '1999-04-06 21:20:16' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.70' and packetime between '1999-04-06 21:20:19' and '1999-04-06 21:20:22' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.80' and packetime between '1999-04-06 21:20:25' and '1999-04-06 21:20:28' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.80' and packetime between '1999-04-06 21:20:31' and '1999-04-06 21:20:34' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.80' and packetime between '1999-04-06 21:20:37' and '1999-04-06 21:20:40' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.80' and packetime between '1999-04-06 21:20:43' and '1999-04-06 21:20:46' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.80' and packetime between '1999-04-06 21:20:49' and '1999-04-06 21:20:52' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.90' and packetime between '1999-04-06 21:20:55' and '1999-04-06 21:20:58' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.90' and packetime between '1999-04-06 21:21:01' and '1999-04-06 21:21:04' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.90' and packetime between '1999-04-06 21:21:07' and '1999-04-06 21:21:10' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.90' and packetime between '1999-04-06 21:21:13' and '1999-04-06 21:21:16' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.90' and packetime between '1999-04-06 21:21:19' and '1999-04-06 21:21:22' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.20' and packetime between '1999-04-06 21:21:25' and '1999-04-06 21:21:28' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.20' and packetime between '1999-04-06 21:21:31' and '1999-04-06 21:21:34' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.20' and packetime between '1999-04-06 21:21:37' and '1999-04-06 21:21:40' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.20' and packetime between '1999-04-06 21:21:43' and '1999-04-06 21:21:46' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.20' and packetime between '1999-04-06 21:21:49' and '1999-04-06 21:21:52' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.169' and packetime between '1999-04-06 21:21:55' and '1999-04-06 21:21:58' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.169' and packetime between '1999-04-06 21:22:01' and '1999-04-06 21:22:04' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.169' and packetime between '1999-04-06 21:22:07' and '1999-04-06 21:22:10' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.169' and packetime between '1999-04-06 21:22:13' and '1999-04-06 21:22:16' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.169' and packetime between '1999-04-06 21:22:19' and '1999-04-06 21:22:22' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.207' and packetime between '1999-04-06 21:22:25' and '1999-04-06 21:22:28' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.207' and packetime between '1999-04-06 21:22:31' and '1999-04-06 21:22:34' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.207' and packetime between '1999-04-06 21:22:37' and '1999-04-06 21:22:40' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.207' and packetime between '1999-04-06 21:22:43' and '1999-04-06 21:22:46' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.207' and packetime between '1999-04-06 21:22:49' and '1999-04-06 21:22:52' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.84' and packetime between '1999-04-06 21:22:55' and '1999-04-06 21:22:58' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.84' and packetime between '1999-04-06 21:23:01' and '1999-04-06 21:23:04' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.84' and packetime between '1999-04-06 21:23:07' and '1999-04-06 21:23:10' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.84' and packetime between '1999-04-06 21:23:13' and '1999-04-06 21:23:16' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.84' and packetime between '1999-04-06 21:23:19' and '1999-04-06 21:23:22' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.0.1' and packetime between '1999-04-06 21:23:25' and '1999-04-06 21:23:28' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.0.1' and packetime between '1999-04-06 21:23:31' and '1999-04-06 21:23:34' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.0.1' and packetime between '1999-04-06 21:23:37' and '1999-04-06 21:23:40' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.0.1' and packetime between '1999-04-06 21:23:43' and '1999-04-06 21:23:46' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.0.1' and packetime between '1999-04-06 21:23:49' and '1999-04-06 21:23:52' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.194' and packetime between '1999-04-06 21:23:55' and '1999-04-06 21:23:58' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.194' and packetime between '1999-04-06 21:24:01' and '1999-04-06 21:24:04' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.194' and packetime between '1999-04-06 21:24:07' and '1999-04-06 21:24:10' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.194' and packetime between '1999-04-06 21:24:13' and '1999-04-06 21:24:16' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.194' and packetime between '1999-04-06 21:24:19' and '1999-04-06 21:24:22' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.115.234' and packetime between '1999-04-06 21:24:25' and '1999-04-06 21:24:28' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.115.234' and packetime between '1999-04-06 21:24:31' and '1999-04-06 21:24:34' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.115.234' and packetime between '1999-04-06 21:24:37' and '1999-04-06 21:24:40' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.115.234' and packetime between '1999-04-06 21:24:43' and '1999-04-06 21:24:46' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.115.234' and packetime between '1999-04-06 21:24:49' and '1999-04-06 21:24:52' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.115.5' and packetime between '1999-04-06 21:24:55' and '1999-04-06 21:24:58' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.115.5' and packetime between '1999-04-06 21:25:01' and '1999-04-06 21:25:04' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.115.5' and packetime between '1999-04-06 21:25:07' and '1999-04-06 21:25:10' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.115.5' and packetime between '1999-04-06 21:25:13' and '1999-04-06 21:25:16' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.115.5' and packetime between '1999-04-06 21:25:19' and '1999-04-06 21:25:22' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.115.87' and packetime between '1999-04-06 21:25:25' and '1999-04-06 21:25:28' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.115.87' and packetime between '1999-04-06 21:25:31' and '1999-04-06 21:25:34' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.115.87' and packetime between '1999-04-06 21:25:37' and '1999-04-06 21:25:40' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.115.87' and packetime between '1999-04-06 21:25:43' and '1999-04-06 21:25:46' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.115.87' and packetime between '1999-04-06 21:25:49' and '1999-04-06 21:25:52' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.116.194' and packetime between '1999-04-06 21:25:55' and '1999-04-06 21:25:58' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.116.194' and packetime between '1999-04-06 21:26:01' and '1999-04-06 21:26:04' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.116.194' and packetime between '1999-04-06 21:26:07' and '1999-04-06 21:26:10' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.116.194' and packetime between '1999-04-06 21:26:13' and '1999-04-06 21:26:16' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.116.194' and packetime between '1999-04-06 21:26:20' and '1999-04-06 21:26:23' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.116.201' and packetime between '1999-04-06 21:26:26' and '1999-04-06 21:26:29' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.116.201' and packetime between '1999-04-06 21:26:32' and '1999-04-06 21:26:35' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.116.201' and packetime between '1999-04-06 21:26:38' and '1999-04-06 21:26:41' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.116.201' and packetime between '1999-04-06 21:26:44' and '1999-04-06 21:26:47' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.116.201' and packetime between '1999-04-06 21:26:50' and '1999-04-06 21:26:53' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.116.44' and packetime between '1999-04-06 21:26:56' and '1999-04-06 21:26:59' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.116.44' and packetime between '1999-04-06 21:27:02' and '1999-04-06 21:27:05' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.116.44' and packetime between '1999-04-06 21:27:08' and '1999-04-06 21:27:11' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.116.44' and packetime between '1999-04-06 21:27:14' and '1999-04-06 21:27:17' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.116.44' and packetime between '1999-04-06 21:27:20' and '1999-04-06 21:27:23' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.10' and packetime between '1999-04-06 21:27:26' and '1999-04-06 21:27:29' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.10' and packetime between '1999-04-06 21:27:32' and '1999-04-06 21:27:35' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.10' and packetime between '1999-04-06 21:27:38' and '1999-04-06 21:27:41' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.10' and packetime between '1999-04-06 21:27:44' and '1999-04-06 21:27:47' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.10' and packetime between '1999-04-06 21:27:50' and '1999-04-06 21:27:53' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.132' and packetime between '1999-04-06 21:27:56' and '1999-04-06 21:27:59' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.132' and packetime between '1999-04-06 21:28:02' and '1999-04-06 21:28:05' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.132' and packetime between '1999-04-06 21:28:08' and '1999-04-06 21:28:11' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.132' and packetime between '1999-04-06 21:28:14' and '1999-04-06 21:28:17' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.132' and packetime between '1999-04-06 21:28:20' and '1999-04-06 21:28:23' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.52' and packetime between '1999-04-06 21:28:26' and '1999-04-06 21:28:29' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.52' and packetime between '1999-04-06 21:28:32' and '1999-04-06 21:28:35' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.52' and packetime between '1999-04-06 21:28:38' and '1999-04-06 21:28:41' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.52' and packetime between '1999-04-06 21:28:44' and '1999-04-06 21:28:47' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.52' and packetime between '1999-04-06 21:28:50' and '1999-04-06 21:28:53' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.168' and packetime between '1999-04-06 21:28:56' and '1999-04-06 21:28:59' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.168' and packetime between '1999-04-06 21:29:02' and '1999-04-06 21:29:05' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.168' and packetime between '1999-04-06 21:29:08' and '1999-04-06 21:29:11' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.168' and packetime between '1999-04-06 21:29:14' and '1999-04-06 21:29:17' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.168' and packetime between '1999-04-06 21:29:20' and '1999-04-06 21:29:23' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.111' and packetime between '1999-04-06 21:29:26' and '1999-04-06 21:29:29' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.111' and packetime between '1999-04-06 21:29:32' and '1999-04-06 21:29:35' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.111' and packetime between '1999-04-06 21:29:38' and '1999-04-06 21:29:41' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.111' and packetime between '1999-04-06 21:29:44' and '1999-04-06 21:29:47' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.111' and packetime between '1999-04-06 21:29:50' and '1999-04-06 21:29:53' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.103' and packetime between '1999-04-06 21:29:56' and '1999-04-06 21:29:59' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.103' and packetime between '1999-04-06 21:30:02' and '1999-04-06 21:30:05' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.103' and packetime between '1999-04-06 21:30:08' and '1999-04-06 21:30:11' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.103' and packetime between '1999-04-06 21:30:14' and '1999-04-06 21:30:17' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.117.103' and packetime between '1999-04-06 21:30:20' and '1999-04-06 21:30:23' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.200' and packetime between '1999-04-06 21:30:26' and '1999-04-06 21:30:29' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.200' and packetime between '1999-04-06 21:30:32' and '1999-04-06 21:30:35' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.200' and packetime between '1999-04-06 21:30:38' and '1999-04-06 21:30:41' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.200' and packetime between '1999-04-06 21:30:44' and '1999-04-06 21:30:47' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.200' and packetime between '1999-04-06 21:30:50' and '1999-04-06 21:30:53' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.105' and packetime between '1999-04-06 21:30:56' and '1999-04-06 21:30:59' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.105' and packetime between '1999-04-06 21:31:02' and '1999-04-06 21:31:05' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.105' and packetime between '1999-04-06 21:31:08' and '1999-04-06 21:31:11' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.105' and packetime between '1999-04-06 21:31:14' and '1999-04-06 21:31:17' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.105' and packetime between '1999-04-06 21:31:20' and '1999-04-06 21:31:23' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.204' and packetime between '1999-04-06 21:31:26' and '1999-04-06 21:31:29' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.204' and packetime between '1999-04-06 21:31:32' and '1999-04-06 21:31:35' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.204' and packetime between '1999-04-06 21:31:38' and '1999-04-06 21:31:41' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.204' and packetime between '1999-04-06 21:31:44' and '1999-04-06 21:31:47' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.204' and packetime between '1999-04-06 21:31:50' and '1999-04-06 21:31:53' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.149' and packetime between '1999-04-06 21:31:56' and '1999-04-06 21:31:59' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.149' and packetime between '1999-04-06 21:32:02' and '1999-04-06 21:32:05' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.149' and packetime between '1999-04-06 21:32:08' and '1999-04-06 21:32:11' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.149' and packetime between '1999-04-06 21:32:14' and '1999-04-06 21:32:17' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.149' and packetime between '1999-04-06 21:32:20' and '1999-04-06 21:32:23' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.207' and packetime between '1999-04-06 21:32:27' and '1999-04-06 21:32:30' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.207' and packetime between '1999-04-06 21:32:33' and '1999-04-06 21:32:36' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.207' and packetime between '1999-04-06 21:32:39' and '1999-04-06 21:32:42' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.207' and packetime between '1999-04-06 21:32:45' and '1999-04-06 21:32:48' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.207' and packetime between '1999-04-06 21:32:51' and '1999-04-06 21:32:54' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.100' and packetime between '1999-04-06 21:32:57' and '1999-04-06 21:33:00' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.100' and packetime between '1999-04-06 21:33:03' and '1999-04-06 21:33:06' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.100' and packetime between '1999-04-06 21:33:09' and '1999-04-06 21:33:12' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.100' and packetime between '1999-04-06 21:33:15' and '1999-04-06 21:33:18' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.118.100' and packetime between '1999-04-06 21:33:21' and '1999-04-06 21:33:24' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.50' and packetime between '1999-04-06 21:33:27' and '1999-04-06 21:33:30' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.50' and packetime between '1999-04-06 21:33:33' and '1999-04-06 21:33:36' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.50' and packetime between '1999-04-06 21:33:39' and '1999-04-06 21:33:42' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.50' and packetime between '1999-04-06 21:33:45' and '1999-04-06 21:33:48' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.113.50' and packetime between '1999-04-06 21:33:51' and '1999-04-06 21:33:54' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.50' and packetime between '1999-04-06 21:33:57' and '1999-04-06 21:34:00' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.50' and packetime between '1999-04-06 21:34:03' and '1999-04-06 21:34:06' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.50' and packetime between '1999-04-06 21:34:09' and '1999-04-06 21:34:12' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.50' and packetime between '1999-04-06 21:34:15' and '1999-04-06 21:34:18' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.50' and packetime between '1999-04-06 21:34:21' and '1999-04-06 21:34:24' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.50' and packetime between '1999-04-06 21:34:27' and '1999-04-06 21:34:30' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.50' and packetime between '1999-04-06 21:34:33' and '1999-04-06 21:34:36' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.50' and packetime between '1999-04-06 21:34:39' and '1999-04-06 21:34:42' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.50' and packetime between '1999-04-06 21:34:45' and '1999-04-06 21:34:48' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.112.50' and packetime between '1999-04-06 21:34:51' and '1999-04-06 21:34:54' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.50' and packetime between '1999-04-06 21:34:57' and '1999-04-06 21:35:00' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.50' and packetime between '1999-04-06 21:35:03' and '1999-04-06 21:35:06' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.50' and packetime between '1999-04-06 21:35:09' and '1999-04-06 21:35:12' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.50' and packetime between '1999-04-06 21:35:15' and '1999-04-06 21:35:18' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '195.73.151.50' and destIP='172.16.114.50' and packetime between '1999-04-06 21:35:21' and '1999-04-06 21:35:24' and destPort in (80)
UPDATE TCP_52_out SET category =1 where srcIP = '172.16.118.20' and destIP='172.16.114.50' and packetime between '1999-04-06 21:45:02' and '1999-04-06 21:46:30' and sourcePort in (20,21,25) and destPort in (23)
UPDATE TCP_52_out SET category =1 where srcIP = '172.16.114.50' and destIP='172.16.118.20' and packetime between '1999-04-06 21:45:24' and '1999-04-06 21:46:10' and destPort in (80)
--
UPDATE TCP_53_out SET category =1 where srcIP = '135.8.60.182' and destIP='172.16.112.50' and packetime between '1999-04-07 05:04:19' and '1999-04-07 05:08:21' and destPort in (23)
UPDATE TCP_53_out SET category =1 where srcIP = '152.204.242.193' and destIP='172.16.112.50' and packetime between '1999-04-07 08:46:02' and '1999-04-07 08:46:27' and destPort in (6000)
UPDATE TCP_53_out SET category =1 where srcIP = '209.1.12.46' and destIP='172.16.114.50' and packetime between '1999-04-07 08:58:16' and '1999-04-07 08:58:17' and destPort in (80)
UPDATE TCP_53_out SET category =1 where destIP='172.16.112.50' and packetime between '1999-04-07 09:44:00' and '1999-04-07 09:59:00'--src console
UPDATE TCP_53_out SET category =1 where srcIP = '209.167.99.71' and destIP='172.16.112.100' and packetime between '1999-04-07 09:50:33' and '1999-04-07 09:50:38' and destPort in (25,12345,12346)
UPDATE TCP_53_out SET category =1 where srcIP = '152.204.242.193' and destIP='172.16.114.50' and packetime between '1999-04-07 10:26:12' and '1999-04-07 10:26:16' and destPort in (80)
UPDATE TCP_53_out SET category =1 where srcIP = '172.16.113.84' and destIP='197.182.91.233' and packetime between '1999-04-07 11:06:56' and '1999-04-07 11:06:57' and destPort in (25)
UPDATE TCP_53_out SET category =1 where srcIP = '197.182.91.233' and destIP='172.16.114.50' and packetime between '1999-04-07 11:32:16' and '1999-04-07 11:32:17' and destPort in (23)
UPDATE TCP_53_out SET category =1 where srcIP = '197.182.91.233' and destIP='172.16.114.50' and packetime between '1999-04-07 11:34:17' and '1999-04-07 11:34:18' and destPort in (23)
UPDATE TCP_53_out SET category =1 where srcIP = '197.182.91.233' and destIP='172.16.114.50' and packetime between '1999-04-07 11:36:18' and '1999-04-07 11:36:19'  and destPort in (23)
UPDATE TCP_53_out SET category =1 where srcIP = '197.182.91.233' and destIP='172.16.114.50' and packetime between '1999-04-07 11:38:39' and '1999-04-07 11:38:40'  and destPort in (23)
UPDATE TCP_53_out SET category =1 where srcIP = '197.182.91.233' and destIP='172.16.114.50' and packetime between '1999-04-07 11:40:40' and '1999-04-07 11:40:41'  and destPort in (23)
UPDATE TCP_53_out SET category =1 where srcIP = '197.182.91.233' and destIP='172.16.114.50' and packetime between '1999-04-07 11:43:00' and '1999-04-07 11:43:01'  and destPort in (23)
UPDATE TCP_53_out SET category =1 where srcIP = '197.182.91.233' and destIP='172.16.114.50' and packetime between '1999-04-07 11:45:20' and '1999-04-07 11:45:21'  and destPort in (23)
UPDATE TCP_53_out SET category =1 where srcIP = '209.167.99.71' and destIP='172.16.112.100' and packetime between '1999-04-07 12:03:45' and '1999-04-07 12:05:01' and destPort in (25,12345,12346)
UPDATE TCP_53_out SET category =1 where srcIP = '204.97.153.43' and destIP='172.16.114.50' and packetime between '1999-04-07 12:37:10' and '1999-04-07 12:37:11' and destPort <11
UPDATE TCP_53_out SET category =1 where srcIP = '204.97.153.43' and destIP='172.16.114.50' and packetime between '1999-04-07 12:37:16' and '1999-04-07 12:37:17' and destPort <11
UPDATE TCP_53_out SET category =1 where srcIP = '204.97.153.43' and destIP='172.16.114.50' and packetime between '1999-04-07 12:38:16' and '1999-04-07 12:38:17' and destPort <11
UPDATE TCP_53_out SET category =1 where srcIP = '204.97.153.43' and destIP='172.16.114.50' and packetime between '1999-04-07 12:39:16' and '1999-04-07 12:39:17' and destPort <11
UPDATE TCP_53_out SET category =1 where srcIP = '204.97.153.43' and destIP='172.16.114.50' and packetime between '1999-04-07 12:40:16' and '1999-04-07 12:40:17' and destPort <11
UPDATE TCP_53_out SET category =1 where srcIP = '204.97.153.43' and destIP='172.16.114.50' and packetime between '1999-04-07 12:41:16' and '1999-04-07 12:41:17' and destPort <11
UPDATE TCP_53_out SET category =1 where srcIP = '204.97.153.43' and destIP='172.16.114.50' and packetime between '1999-04-07 12:42:17' and '1999-04-07 12:42:18' and destPort <11
UPDATE TCP_53_out SET category =1 where srcIP = '204.97.153.43' and destIP='172.16.114.50' and packetime between '1999-04-07 12:43:17' and '1999-04-07 12:43:18' and destPort <11
UPDATE TCP_53_out SET category =1 where srcIP = '204.97.153.43' and destIP='172.16.114.50' and packetime between '1999-04-07 12:43:23' and '1999-04-07 12:43:24' and destPort <11
UPDATE TCP_53_out SET category =1 where srcIP = '204.97.153.43' and destIP='172.16.114.50' and packetime between '1999-04-07 12:44:29' and '1999-04-07 12:44:30' and destPort <11
UPDATE TCP_53_out SET category =1 where srcIP = '204.97.153.43' and destIP='172.16.114.50' and packetime between '1999-04-07 12:45:29' and '1999-04-07 12:45:30' and destPort <11
UPDATE TCP_53_out SET category =1 where srcIP = '204.97.153.43' and destIP='172.16.114.50' and packetime between '1999-04-07 12:45:35' and '1999-04-07 12:45:36' and destPort <11
UPDATE TCP_53_out SET category =1 where srcIP = '204.97.153.43' and destIP='172.16.114.50' and packetime between '1999-04-07 12:46:41' and '1999-04-07 12:46:42' and destPort <11
UPDATE TCP_53_out SET category =1 where srcIP = '209.17.189.98' and destIP='172.16.112.207' and packetime between '1999-04-07 13:33:17' and '1999-04-07 13:44:03'  and destPort in (23)
UPDATE TCP_53_out SET category =1 where srcIP = '172.16.114.169' and destIP='172.16.112.50' and packetime between '1999-04-07 13:40:24' and '1999-04-07 13:40:25'  and destPort in (25)
UPDATE TCP_53_out SET category =1 where srcIP = '172.16.114.169' and destIP='172.16.112.50' and packetime between '1999-04-07 13:43:25' and '1999-04-07 13:43:26'  and destPort in (25)
UPDATE TCP_53_out SET category =1 where srcIP = '172.16.114.169' and destIP='172.16.112.50' and packetime between '1999-04-07 13:46:45' and '1999-04-07 13:46:46'  and destPort in (25)
UPDATE TCP_53_out SET category =1 where srcIP = '172.16.114.169' and destIP='172.16.112.50' and packetime between '1999-04-07 13:50:05' and '1999-04-07 13:50:06'  and destPort in (25)
UPDATE TCP_53_out SET category =1 where srcIP = '172.16.114.169' and destIP='172.16.112.50' and packetime between '1999-04-07 13:53:25' and '1999-04-07 13:53:26'  and destPort in (25)
UPDATE TCP_53_out SET category =1 where srcIP = '172.16.114.169' and destIP='172.16.112.50' and packetime between '1999-04-07 13:56:29' and '1999-04-07 13:56:30'  and destPort in (25)
UPDATE TCP_53_out SET category =1 where srcIP = '172.16.114.169' and destIP='172.16.112.50' and packetime between '1999-04-07 13:59:33' and '1999-04-07 13:59:34'  and destPort in (25)
UPDATE TCP_53_out SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:49:35' and '1999-04-07 14:49:37'  and destPort in (161)
UPDATE TCP_53_out SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:49:42' and '1999-04-07 14:49:43'  and destPort in (161)
UPDATE TCP_53_out SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:49:47' and '1999-04-07 14:49:48'  and destPort in (161)
UPDATE TCP_53_out SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:49:52' and '1999-04-07 14:49:53'  and destPort in (161)
UPDATE TCP_53_out SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:49:57' and '1999-04-07 14:49:58'  and destPort in (161)
UPDATE TCP_53_out SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:50:02' and '1999-04-07 14:50:03'  and destPort in (161)
UPDATE TCP_53_out SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:50:07' and '1999-04-07 14:50:08'  and destPort in (161)
UPDATE TCP_53_out SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:50:12' and '1999-04-07 14:50:13'  and destPort in (161)
UPDATE TCP_53_out SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:50:18' and '1999-04-07 14:50:19'  and destPort in (161)
UPDATE TCP_53_out SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:50:23' and '1999-04-07 14:50:24'  and destPort in (161)
UPDATE TCP_53_out SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:50:28' and '1999-04-07 14:50:29'  and destPort in (161)
UPDATE TCP_53_out SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:50:33' and '1999-04-07 14:50:34'  and destPort in (161)
UPDATE TCP_53_out SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:50:38' and '1999-04-07 14:50:39'  and destPort in (161)
UPDATE TCP_53_out SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:50:43' and '1999-04-07 14:50:44'  and destPort in (161)
UPDATE TCP_53_out SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:50:48' and '1999-04-07 14:50:49'  and destPort in (161)
UPDATE TCP_53_out SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:50:53' and '1999-04-07 14:50:54'  and destPort in (161)
UPDATE TCP_53_out SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:50:58' and '1999-04-07 14:50:59'  and destPort in (161)
UPDATE TCP_53_out SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:51:03' and '1999-04-07 14:51:04'  and destPort in (161)
UPDATE TCP_53_out SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:51:08' and '1999-04-07 14:51:09'  and destPort in (161)
UPDATE TCP_53_out SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:51:13' and '1999-04-07 14:51:14'  and destPort in (161)
UPDATE TCP_53_out SET category =1 where srcIP = '207.230.54.203' and destIP='172.16.0.1' and packetime between '1999-04-07 14:51:19' and '1999-04-07 14:51:20'  and destPort in (161)
UPDATE TCP_53_out SET category =1 where srcIP = '172.16.117.52' and destIP='172.16.113.50' and packetime between '1999-04-07 15:01:16' and '1999-04-07 15:32:21'  and destPort in (25)
UPDATE TCP_53_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.114.50' and packetime between '1999-04-07 15:26:15' and '1999-04-07 15:28:04'  and destPort in (80)
UPDATE TCP_53_out SET category =1 where srcIP = '195.115.218.108' and destIP='172.16.112.50' and packetime between '1999-04-07 15:54:19' and '1999-04-07 15:54:20'  and destPort in (23,25)
UPDATE TCP_53_out SET category =1 where srcIP = '195.115.218.108' and destIP='172.16.112.50' and packetime between '1999-04-07 15:59:19' and '1999-04-07 22:50:59'  and destPort in (23,25)
UPDATE TCP_53_out SET category =1 where srcIP = '172.16.117.52' and destIP='172.16.114.50' and packetime between '1999-04-07 17:13:17' and '1999-04-07 17:21:56'  and destPort in (80)
UPDATE TCP_53_out SET category =1 where srcIP = '209.30.71.165' and destIP='172.16.112.50' and packetime between '1999-04-07 19:51:19' and '1999-04-07 19:51:24'  and destPort < 101 and destPort <>53
UPDATE TCP_53_out SET category =1 where srcIP = '209.30.71.165' and destIP='172.16.112.50' and packetime between '1999-04-07 19:51:25' and '1999-04-07 19:51:39'  and destPort < 101 and destPort <>53
UPDATE TCP_53_out SET category =1 where srcIP = '209.30.71.165' and destIP='172.16.112.50' and packetime between '1999-04-07 19:51:40' and '1999-04-07 19:51:51'  and destPort < 101 and destPort <>53
UPDATE TCP_53_out SET category =1 where srcIP = '209.30.71.165' and destIP='172.16.112.50' and packetime between '1999-04-07 19:51:52' and '1999-04-07 19:52:05'  and destPort < 101 and destPort <>53
UPDATE TCP_53_out SET category =1 where srcIP = '209.30.71.165' and destIP='172.16.112.50' and packetime between '1999-04-07 19:52:06' and '1999-04-07 19:52:15'  and destPort < 101 and destPort <>53
UPDATE TCP_53_out SET category =1 where srcIP = '209.30.71.165' and destIP='172.16.112.50' and packetime between '1999-04-07 19:52:16' and '1999-04-07 19:52:19'  and destPort < 101 and destPort <>53
UPDATE TCP_53_out SET category =1 where srcIP = '209.30.71.165' and destIP='172.16.112.50' and packetime between '1999-04-07 19:52:20' and '1999-04-07 19:52:35'  and destPort < 101 and destPort <>53
UPDATE TCP_53_out SET category =1 where srcIP = '209.30.71.165' and destIP='172.16.112.50' and packetime between '1999-04-07 19:52:36' and '1999-04-07 19:52:48'  and destPort < 101 and destPort <>53
UPDATE TCP_53_out SET category =1 where srcIP = '209.30.71.165' and destIP='172.16.112.50' and packetime between '1999-04-07 19:52:49' and '1999-04-07 19:53:02'  and destPort < 101 and destPort <>53
UPDATE TCP_53_out SET category =1 where srcIP = '209.30.71.165' and destIP='172.16.112.50' and packetime between '1999-04-07 19:53:03' and '1999-04-07 19:53:07'  and destPort < 101 and destPort <>53
--
UPDATE TCP_54_out SET category =1 where destIP='172.16.112.50' and packetime between '1999-04-08 08:33:00' and '1999-04-08 08:36:00'
UPDATE TCP_54_out SET category =1 where srcIP = '206.48.44.50' and destIP='172.16.114.50' and packetime between '1999-04-08 09:01:08' and '1999-04-08 09:01:13' and destPort in (80) 
UPDATE TCP_54_out SET category =1 where srcIP = '172.16.112.149' and destIP='172.16.112.100' and packetime between '1999-04-08 09:16:20' and '1999-04-08 09:17:38' and destPort in (20,21,23)
UPDATE TCP_54_out SET category =1 where srcIP = '172.16.112.149' and destIP='172.16.112.100' and packetime between '1999-04-08 09:17:52' and '1999-04-08 09:27:35'  and destPort in (20,21,23)
UPDATE TCP_54_out SET category =1 where srcIP = '206.48.44.50' and destIP='172.16.114.50' and packetime between '1999-04-08 09:31:33' and '1999-04-08 09:31:41' and destPort in (80) 
UPDATE TCP_54_out SET category =1 where srcIP = '206.48.44.50' and destIP='172.16.114.50' and packetime between '1999-04-08 09:31:43' and '1999-04-08 09:31:49' and destPort in (80) 
UPDATE TCP_54_out SET category =1 where srcIP = '206.48.44.50' and destIP='172.16.114.50' and packetime between '1999-04-08 09:32:03' and '1999-04-08 09:32:10' and destPort in (80) 
UPDATE TCP_54_out SET category =1 where srcIP = '206.48.44.50' and destIP='172.16.114.50' and packetime between '1999-04-08 09:32:19' and '1999-04-08 09:32:30' and destPort in (80) 
UPDATE TCP_54_out SET category =1 where srcIP = '206.48.44.50' and destIP='172.16.114.50' and packetime between '1999-04-08 09:32:37' and '1999-04-08 09:32:42' and destPort in (80) 
UPDATE TCP_54_out SET category =1 where srcIP = '206.48.44.50' and destIP='172.16.114.50' and packetime between '1999-04-08 09:32:48' and '1999-04-08 09:32:54' and destPort in (80) 
UPDATE TCP_54_out SET category =1 where srcIP = '172.16.112.100' and destIP='172.16.112.100' and packetime between '1999-04-08 10:21:00' and '1999-04-08 10:36:00' --i
UPDATE TCP_54_out SET category =1 where srcIP = '153.10.8.174' and destIP='172.16.112.50' and packetime between '1999-04-08 10:34:11' and '1999-04-08 10:34:12'  and destPort in (22,79,514)
UPDATE TCP_54_out SET category =1 where srcIP = '153.10.8.174' and destIP='172.16.112.50' and packetime between '1999-04-08 10:37:02' and '1999-04-08 10:37:03'  and destPort in (22,79,514)
UPDATE TCP_54_out SET category =1 where srcIP = '153.10.8.174' and destIP='172.16.112.50' and packetime between '1999-04-08 10:39:54' and '1999-04-08 10:39:55'  and destPort in (22,79,514)
UPDATE TCP_54_out SET category =1 where srcIP = '172.16.112.149' and destIP='172.16.112.100' and packetime between '1999-04-08 11:14:29' and '1999-04-08 11:20:07' and destPort in (20,21,23)
UPDATE TCP_54_out SET category =1 where srcIP = '206.48.44.18' and destIP='172.16.112.100' and packetime between '1999-04-08 11:26:37' and '1999-04-08 11:42:46' and destPort in (20,21,23,80,139)
UPDATE TCP_54_out SET category =1 where srcIP = '194.7.248.153' and destIP='172.16.112.100' and packetime between '1999-04-08 11:52:05' and '1999-04-08 11:57:36' and destPort in (23,80)
UPDATE TCP_54_out SET category =1 where srcIP = '194.7.248.153' and destIP='172.16.112.100' and packetime between '1999-04-08 11:57:01' and '1999-04-08 12:12:04' and destPort in (23,80)
UPDATE TCP_54_out SET category =1 where srcIP = '194.7.248.153' and destIP='172.16.112.100' and packetime between '1999-04-08 12:04:20' and '1999-04-08 12:07:44' and destPort in (23,80)
UPDATE TCP_54_out SET category =1 where srcIP = '172.16.112.50' and destIP='196.37.75.158' and packetime between '1999-04-08 12:06:30' and '1999-04-08 12:06:31' and destPort in (8000) 
UPDATE TCP_54_out SET category =1 where srcIP = '172.16.112.50' and destIP='196.37.75.158' and packetime between '1999-04-08 12:07:00' and '1999-04-08 12:07:01' and destPort in (8000) 
UPDATE TCP_54_out SET category =1 where srcIP = '172.16.112.50' and destIP='196.37.75.158' and packetime between '1999-04-08 12:07:30' and '1999-04-08 12:07:31' and destPort in (8000) 
UPDATE TCP_54_out SET category =1 where srcIP = '172.16.112.50' and destIP='196.37.75.158' and packetime between '1999-04-08 12:08:00' and '1999-04-08 12:08:01' and destPort in (8000) 
UPDATE TCP_54_out SET category =1 where srcIP = '172.16.112.50' and destIP='196.37.75.158' and packetime between '1999-04-08 12:08:30' and '1999-04-08 12:08:31' and destPort in (8000) 
UPDATE TCP_54_out SET category =1 where srcIP = '172.16.112.50' and destIP='196.37.75.158' and packetime between '1999-04-08 12:09:00' and '1999-04-08 12:09:01' and destPort in (8000) 
UPDATE TCP_54_out SET category =1 where srcIP = '172.16.112.50' and destIP='196.37.75.158' and packetime between '1999-04-08 12:09:30' and '1999-04-08 12:09:31' and destPort in (8000) 
UPDATE TCP_54_out SET category =1 where srcIP = '172.16.112.50' and destIP='196.37.75.158' and packetime between '1999-04-08 12:10:00' and '1999-04-08 12:10:01' and destPort in (8000) 
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.112.50' and packetime between '1999-04-08 12:57:17' and '1999-04-08 12:59:34' and destPort in (20,21,23)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.112.50' and packetime between '1999-04-08 13:11:54' and '1999-04-08 13:37:27' and destPort in (20,21,23)
UPDATE TCP_54_out SET category =1 where srcIP = '209.74.60.168' and destIP='172.16.114.50' and packetime between '1999-04-08 14:58:29' and '1999-04-08 15:00:41' and destPort < 10000
UPDATE TCP_54_out SET category =1 where srcIP = '199.227.99.125' and destIP='172.16.114.50' and packetime between '1999-04-08 15:53:18' and '1999-04-08 16:08:19' and destPort in (23)
UPDATE TCP_54_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.100' and packetime between '1999-04-08 16:03:15' and '1999-04-08 16:03:22' and destPort in (20,21,23)
UPDATE TCP_54_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.100' and packetime between '1999-04-08 16:03:24' and '1999-04-08 16:10:06' and destPort in (20,21,23)
UPDATE TCP_54_out SET category =1 where srcIP = '208.240.124.83' and destIP='172.16.112.100' and packetime between '1999-04-08 16:20:08' and '1999-04-08 16:25:11' and destPort in (20,21,23)
UPDATE TCP_54_out SET category =1 where srcIP = '172.16.117.103' and LEFT(destIP,11)='172.16.112.' and packetime between '1999-04-08 17:01:19' and '1999-04-08 17:02:21' and destPort in (21)
UPDATE TCP_54_out SET category =1 where srcIP in( '172.16.112.5','172.16.112.10','207.136.86.223') and destIP='172.16.112.1' and packetime between '1999-04-08 17:16:10' and '1999-04-08 17:16:11' --i src dest
UPDATE TCP_54_out SET category =1 where srcIP in( '172.16.112.5','172.16.112.10','207.136.86.223') and destIP='172.16.112.2' and packetime between '1999-04-08 17:16:20' and '1999-04-08 17:16:21' --i src dest
UPDATE TCP_54_out SET category =1 where srcIP in( '172.16.112.5','172.16.112.10','207.136.86.223') and destIP='172.16.112.3' and packetime between '1999-04-08 17:16:30' and '1999-04-08 17:16:31' --i src dest
UPDATE TCP_54_out SET category =1 where srcIP in( '172.16.112.5','172.16.112.10','207.136.86.223') and destIP='172.16.112.4' and packetime between '1999-04-08 17:16:40' and '1999-04-08 17:16:41' --i src dest
UPDATE TCP_54_out SET category =1 where srcIP in( '172.16.112.5','172.16.112.10','207.136.86.223') and destIP='172.16.112.5' and packetime between '1999-04-08 17:16:50' and '1999-04-08 17:16:51' --i src dest
UPDATE TCP_54_out SET category =1 where srcIP in( '172.16.112.5','172.16.112.10','207.136.86.223') and destIP='207.136.86.223' and packetime between '1999-04-08 17:16:50' and '1999-04-08 17:16:51' --i src dest
UPDATE TCP_54_out SET category =1 where srcIP in( '172.16.112.5','172.16.112.10','207.136.86.223') and destIP='172.16.112.6' and packetime between '1999-04-08 17:17:00' and '1999-04-08 17:17:01' --i src dest
UPDATE TCP_54_out SET category =1 where srcIP in( '172.16.112.5','172.16.112.10','207.136.86.223') and destIP='172.16.112.7' and packetime between '1999-04-08 17:17:10' and '1999-04-08 17:17:11' --i src dest
UPDATE TCP_54_out SET category =1 where srcIP in( '172.16.112.5','172.16.112.10','207.136.86.223') and destIP='172.16.112.8' and packetime between '1999-04-08 17:17:20' and '1999-04-08 17:17:21' --i src dest
UPDATE TCP_54_out SET category =1 where srcIP in( '172.16.112.5','172.16.112.10','207.136.86.223') and destIP='172.16.112.9' and packetime between '1999-04-08 17:17:30' and '1999-04-08 17:17:31' --i src dest
UPDATE TCP_54_out SET category =1 where srcIP in( '172.16.112.5','172.16.112.10','207.136.86.223') and destIP='172.16.112.10' and packetime between '1999-04-08 17:17:40' and '1999-04-08 17:17:41' --i src dest
UPDATE TCP_54_out SET category =1 where srcIP in( '172.16.112.5','172.16.112.10','207.136.86.223') and destIP='207.136.86.223' and packetime between '1999-04-08 17:17:40' and '1999-04-08 17:17:41' --i src dest
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:50:12' and '1999-04-08 17:50:13' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:50:17' and '1999-04-08 17:50:18' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:50:22' and '1999-04-08 17:50:23' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:50:28' and '1999-04-08 17:50:29' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:50:33' and '1999-04-08 17:50:34' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:50:38' and '1999-04-08 17:50:39' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:50:43' and '1999-04-08 17:50:44' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:50:48' and '1999-04-08 17:50:49' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:50:53' and '1999-04-08 17:50:54' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:50:58' and '1999-04-08 17:50:59' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:51:03' and '1999-04-08 17:51:04' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:51:08' and '1999-04-08 17:51:09' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:51:13' and '1999-04-08 17:51:14' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:51:18' and '1999-04-08 17:51:19' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:51:23' and '1999-04-08 17:51:24' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:51:28' and '1999-04-08 17:51:29' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:51:33' and '1999-04-08 17:51:34' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:51:39' and '1999-04-08 17:51:40' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:51:44' and '1999-04-08 17:51:45' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:51:49' and '1999-04-08 17:51:50' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:51:54' and '1999-04-08 17:51:55' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:51:59' and '1999-04-08 17:52:00' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:52:04' and '1999-04-08 17:52:05' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:52:09' and '1999-04-08 17:52:10' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:52:14' and '1999-04-08 17:52:15' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:52:19' and '1999-04-08 17:52:20' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:52:24' and '1999-04-08 17:52:25' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:52:29' and '1999-04-08 17:52:30' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:52:34' and '1999-04-08 17:52:35' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:52:39' and '1999-04-08 17:52:40' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:52:45' and '1999-04-08 17:52:46' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:52:50' and '1999-04-08 17:52:51' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:52:55' and '1999-04-08 17:52:56' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:53:00' and '1999-04-08 17:53:01' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:53:05' and '1999-04-08 17:53:06' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:53:10' and '1999-04-08 17:53:11' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:53:15' and '1999-04-08 17:53:16' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:53:20' and '1999-04-08 17:53:21' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:53:25' and '1999-04-08 17:53:26' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:53:30' and '1999-04-08 17:53:31' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:53:35' and '1999-04-08 17:53:36' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:53:40' and '1999-04-08 17:53:41' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:53:46' and '1999-04-08 17:53:47' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:53:51' and '1999-04-08 17:53:52' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:53:56' and '1999-04-08 17:53:57' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:54:01' and '1999-04-08 17:54:02' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:54:06' and '1999-04-08 17:54:07' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:54:11' and '1999-04-08 17:54:12' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:54:16' and '1999-04-08 17:54:17' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:54:21' and '1999-04-08 17:54:22' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:54:26' and '1999-04-08 17:54:27' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:54:31' and '1999-04-08 17:54:32' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:54:36' and '1999-04-08 17:54:37' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:54:41' and '1999-04-08 17:54:42' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:54:46' and '1999-04-08 17:54:47' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:54:52' and '1999-04-08 17:54:53' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:54:57' and '1999-04-08 17:54:58' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:55:02' and '1999-04-08 17:55:03' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:55:07' and '1999-04-08 17:55:08' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:55:12' and '1999-04-08 17:55:13' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '194.27.251.21' and destIP='172.16.0.1' and packetime between '1999-04-08 17:55:17' and '1999-04-08 17:55:18' and destPort in (161)
UPDATE TCP_54_out SET category =1 where srcIP = '206.48.44.18' and destIP='172.16.112.100' and packetime between '1999-04-08 18:31:00' and '1999-04-08 18:47:09'  and destPort in (20,21,23,80,139)
UPDATE TCP_54_out SET category =1 where srcIP = '206.48.44.18' and destIP='172.16.112.100' and packetime between '1999-04-08 18:47:10' and '1999-04-08 18:47:11' and destPort in (20,21,23,80,139)
UPDATE TCP_54_out SET category =1 where srcIP = '209.12.13.144' and destIP='172.16.112.20' and packetime between '1999-04-08 19:08:31' and '1999-04-08 19:08:32' and destPort in (53)
UPDATE TCP_54_out SET category =1 where srcIP = '209.30.70.14' and destIP='172.16.112.50' and packetime between '1999-04-08 19:41:14' and '1999-04-08 19:41:55' and destPort in (20,21)
UPDATE TCP_54_out SET category =1 where srcIP = '172.16.112.50' and destIP='209.30.70.14' and packetime between '1999-04-08 19:41:44' and '1999-04-08 19:41:45'
UPDATE TCP_54_out SET category =1 where srcIP = '207.136.86.223' and destIP in('172.16.112.10','172.16.112.20','172.16.112.50','172.16.112.100','172.16.112.149','172.16.112.194','172.16.112.207') and packetime between '1999-04-08 19:58:30' and '1999-04-08 23:59:59' and destPort in (23,25,79,80,110,111,143,6000)
UPDATE TCP_54_out SET category =1 where srcIP = '207.136.86.223' and destIP in('172.16.113.50','172.16.113.84','172.16.113.105','172.16.113.204') and packetime between '1999-04-08 19:58:30' and '1999-04-08 23:59:59'
and destPort in (23,25,79,80,110,111,143,6000)
--
--END
