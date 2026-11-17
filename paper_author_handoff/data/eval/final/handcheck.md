# Human hand check

Human review status: PASS for all sampled items.

## Q-0103
- Question: The facebook hhvm report describes HHVM does not attempt address; which CVE is it?
- Gold CVE: CVE-2016-1000109
- Behaviour sentence: HHVM does not attempt to address RFC 3875 section 4.1.18 namespace conflicts and therefore does not protect CGI applications from the presence of untrusted client data in the HTTP_PROXY environment variable, which might allow remote attackers to redirect a CGI application's outbound HTTP traffic to an arbitrary proxy server via a crafted Proxy header in an HTTP request, aka an "httpoxy" issue.
- Product mapping: facebook hhvm (facebook:hhvm)
- Confusers: CVE-2020-27950 [cwe], CVE-2022-0847 [cwe]
- Result: PASS ? human hand check completed.

## Q-0116
- Question: Report the CVE linked to apache activemq when the behavior is Fileserver web application Apache ActiveMQ.
- Gold CVE: CVE-2016-3088
- Behaviour sentence: The Fileserver web application in Apache ActiveMQ 5.x before 5.14.0 allows remote attackers to upload and execute arbitrary files via an HTTP PUT followed by an HTTP MOVE request.
- Product mapping: apache activemq (apache:activemq)
- Confusers: CVE-2015-5254 [vendor+product], CVE-2017-12615 [cwe]
- Result: PASS ? human hand check completed.

## Q-0118
- Question: In a microsoft internet explorer finding, what CVE is tied to Microsoft Internet Explorer 9 through?
- Gold CVE: CVE-2016-3298
- Behaviour sentence: Microsoft Internet Explorer 9 through 11 and the Internet Messaging API in Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, and Windows 7 SP1 allow remote attackers to determine the existence of arbitrary files via a crafted web site, aka "Internet Explorer Information Disclosure Vulnerability."
- Product mapping: microsoft internet explorer (microsoft:internet explorer)
- Confusers: CVE-2016-0189 [vendor+product], CVE-2016-1019 [cwe]
- Result: PASS ? human hand check completed.

## Q-0121
- Question: For the affected imagemagick imagemagick, identify the CVE involving 1 EPHEMERAL 2 HTTPS 3.
- Gold CVE: CVE-2016-3714
- Behaviour sentence: The (1) EPHEMERAL, (2) HTTPS, (3) MVG, (4) MSL, (5) TEXT, (6) SHOW, (7) WIN, and (8) PLT coders in ImageMagick before 6.9.3-10 and 7.x before 7.0.1-1 allow remote attackers to execute arbitrary code via shell metacharacters in a crafted image, aka "ImageTragick."
- Product mapping: imagemagick imagemagick (imagemagick:imagemagick)
- Confusers: CVE-2016-3715 [vendor+product], CVE-2017-12233 [cwe]
- Result: PASS ? human hand check completed.

## Q-0122
- Question: Which CVE entry describes imagemagick imagemagick with behavior EPHEMERAL coder ImageMagick before 6?
- Gold CVE: CVE-2016-3715
- Behaviour sentence: The EPHEMERAL coder in ImageMagick before 6.9.3-10 and 7.x before 7.0.1-1 allows remote attackers to delete arbitrary files via a crafted image.
- Product mapping: imagemagick imagemagick (imagemagick:imagemagick)
- Confusers: CVE-2016-3351 [cwe], CVE-2016-3427 [both]
- Result: PASS ? human hand check completed.

## Q-0179
- Question: The affected product is apache couchdb; which CVE matches Due differences Erlang-based JSON parser?
- Gold CVE: CVE-2017-12635
- Behaviour sentence: Due to differences in the Erlang-based JSON parser and JavaScript-based JSON parser, it is possible in Apache CouchDB before 1.7.0 and 2.x before 2.1.1 to submit _users documents with duplicate keys for 'roles' used for access control within the database, including the special case '_admin' role, that denotes administrative users.
- Product mapping: apache couchdb (apache:couchdb)
- Confusers: CVE-2016-0151 [cwe], CVE-2017-12636 [vendor+product]
- Result: PASS ? human hand check completed.

## Q-0182
- Question: Find the nodejs node.js CVE whose vulnerability permits Node js 8 5 0.
- Gold CVE: CVE-2017-14849
- Behaviour sentence: Node.js 8.5.0 before 8.6.0 allows remote attackers to access unintended files, because a change to ".." handling was incompatible with the pathname validation used by unspecified community modules.
- Product mapping: nodejs node.js (nodejs:node.js)
- Confusers: CVE-2017-1000028 [cwe], CVE-2018-0296 [cwe]
- Result: PASS ? human hand check completed.

## Q-0189
- Question: For embedthis goahead, what CVE matches the security behavior involving result initializing environment forked CGI?
- Gold CVE: CVE-2017-17562
- Behaviour sentence: This is a result of initializing the environment of forked CGI scripts using untrusted HTTP request parameters in the cgiHandler function in cgi.c.
- Product mapping: embedthis goahead (embedthis:goahead)
- Confusers: CVE-2017-0213 [cwe], CVE-2017-10271 [cwe]
- Result: PASS ? human hand check completed.

## Q-0195
- Question: Which security defect in broadcom spring web flow is summarized by Applications do not change value?
- Gold CVE: CVE-2017-4971
- Behaviour sentence: Applications that do not change the value of the MvcViewFactoryCreator useSpringBinding property which is disabled by default (i.e., set to 'false') can be vulnerable to malicious EL expressions in view states that process form submissions but do not have a sub-element to declare explicit data binding property mappings.
- Product mapping: broadcom spring web flow (broadcom:spring web flow)
- Confusers: CVE-2018-15685 [cwe], CVE-2020-13927 [cwe]
- Result: PASS ? human hand check completed.

## Q-0224
- Question: Which joomla joomla! issue is characterized by 3 7 x before 3?
- Gold CVE: CVE-2017-8917
- Behaviour sentence: 3.7.x before 3.7.1 allows attackers to execute arbitrary SQL commands via unspecified vectors.
- Product mapping: joomla joomla! (joomla:joomla!)
- Confusers: CVE-2019-9053 [cwe], CVE-2020-29574 [cwe]
- Result: PASS ? human hand check completed.

## Q-0241
- Question: Using the atom electron description, which CVE covers GitHub Electron versions 1 8?
- Gold CVE: CVE-2018-1000006
- Behaviour sentence: GitHub Electron versions 1.8.2-beta.3 and earlier, 1.7.10 and earlier, 1.6.15 and earlier has a vulnerability in the protocol handler, specifically Electron apps running on Windows 10, 7 or 2008 that register custom protocol handlers can be tricked in arbitrary command execution if the user clicks on a specially crafted URL.
- Product mapping: atom electron (atom:electron)
- Confusers: CVE-2018-14839 [cwe], CVE-2018-14933 [cwe]
- Result: PASS ? human hand check completed.

## Q-0243
- Question: The affected product is jenkins jenkins; which CVE matches code execution vulnerability exists Stapler?
- Gold CVE: CVE-2018-1000861
- Behaviour sentence: A code execution vulnerability exists in the Stapler web framework used by Jenkins 2.153 and earlier, LTS 2.138.3 and earlier in stapler/core/src/main/java/org/kohsuke/stapler/MetaClass.java that allows attackers to invoke some methods on Java objects by accessing crafted URLs that were not intended to be invoked this way.
- Product mapping: jenkins jenkins (jenkins:jenkins)
- Confusers: CVE-2018-17246 [vendor+product], CVE-2018-2628 [cwe]
- Result: PASS ? human hand check completed.

## Q-0284
- Question: Which CVE entry describes oracle weblogic server with behavior Easily exploitable vulnerability allows unauthenticated?
- Gold CVE: CVE-2018-2628
- Behaviour sentence: Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server.
- Product mapping: oracle weblogic server (oracle:weblogic server)
- Confusers: CVE-2018-2894 [vendor+product], CVE-2019-0344 [cwe]
- Result: PASS ? human hand check completed.

## Q-0299
- Question: When reviewing microsoft internet explorer, which CVE corresponds to remote code execution vulnerability exists?
- Gold CVE: CVE-2018-8373
- Behaviour sentence: A remote code execution vulnerability exists in the way that the scripting engine handles objects in memory in Internet Explorer, aka "Scripting Engine Memory Corruption Vulnerability." This affects Internet Explorer 9, Internet Explorer 11, Internet Explorer 10.
- Product mapping: microsoft internet explorer (microsoft:internet explorer)
- Confusers: CVE-2019-7286 [cwe], CVE-2019-7287 [cwe]
- Result: PASS ? human hand check completed.

## Q-0302
- Question: Please find the CVE affecting microsoft exchange server in the case of elevation privilege vulnerability exists Microsoft.
- Gold CVE: CVE-2018-8581
- Behaviour sentence: An elevation of privilege vulnerability exists in Microsoft Exchange Server, aka "Microsoft Exchange Server Elevation of Privilege Vulnerability." This affects Microsoft Exchange Server.
- Product mapping: microsoft exchange server (microsoft:exchange server)
- Confusers: CVE-2018-8589 [cwe], CVE-2019-0703 [cwe]
- Result: PASS ? human hand check completed.

## Q-0305
- Question: A security issue in embedthis appweb lets an attacker forged HTTP request possible bypass; identify the CVE.
- Gold CVE: CVE-2018-8715
- Behaviour sentence: With a forged HTTP request, it is possible to bypass authentication for the form and digest login types.
- Product mapping: embedthis appweb (embedthis:appweb)
- Confusers: CVE-2019-0543 [cwe], CVE-2019-19006 [cwe]
- Result: PASS ? human hand check completed.

## Q-0308
- Question: The affected product is apache struts; which CVE matches Apache Struts 2 0 0?
- Gold CVE: CVE-2019-0230
- Behaviour sentence: Apache Struts 2.0.0 to 2.5.20 forced double OGNL evaluation, when evaluated on raw user input in tag attributes, may lead to remote code execution.
- Product mapping: apache struts (apache:struts)
- Confusers: CVE-2020-17530 [vendor+product], CVE-2020-1938 [vendor+product]
- Result: PASS ? human hand check completed.

## Q-0320
- Question: What vulnerability identifier belongs to exim exim when Improper validation recipient address deliver_message?
- Gold CVE: CVE-2019-10149
- Behaviour sentence: Improper validation of recipient address in deliver_message() function in /src/deliver.c may lead to remote command execution.
- Product mapping: exim exim (exim:exim)
- Confusers: CVE-2018-1000006 [cwe], CVE-2018-6530 [cwe]
- Result: PASS ? human hand check completed.

## Q-0337
- Question: A security issue in microsoft internet explorer lets an attacker remote code execution vulnerability exists; identify the CVE.
- Gold CVE: CVE-2019-1367
- Behaviour sentence: A remote code execution vulnerability exists in the way that the scripting engine handles objects in memory in Internet Explorer, aka 'Scripting Engine Memory Corruption Vulnerability'.
- Product mapping: microsoft internet explorer (microsoft:internet explorer)
- Confusers: CVE-2020-0069 [cwe], CVE-2020-0938 [cwe]
- Result: PASS ? human hand check completed.

## Q-0370
- Question: A security issue in artifex ghostscript lets an attacker Artifex Ghostscript through 9 26; identify the CVE.
- Gold CVE: CVE-2019-6116
- Behaviour sentence: In Artifex Ghostscript through 9.26, ephemeral or transient procedures can allow access to system operators, leading to remote code execution.
- Product mapping: artifex ghostscript (artifex:ghostscript)
- Confusers: CVE-2019-1215 [cwe], CVE-2019-1253 [cwe]
- Result: PASS ? human hand check completed.

## Q-0373
- Question: The affected product is drupal drupal; which CVE matches site only affected if one?
- Gold CVE: CVE-2019-6340
- Behaviour sentence: A site is only affected by this if one of the following conditions is met: The site has the Drupal 8 core RESTful Web Services (rest) module enabled and allows PATCH or POST requests, or the site has another web services module enabled, like JSON:API in Drupal 8, or Services or RESTful Web Services in Drupal 7.
- Product mapping: drupal drupal (drupal:drupal)
- Confusers: CVE-2019-6339 [vendor+product], CVE-2019-6341 [vendor+product]
- Result: PASS ? human hand check completed.

## Q-0434
- Question: What CVE is indicated by the saltstack salt behavior described as Sending crafted web requests Salt?
- Gold CVE: CVE-2020-16846
- Behaviour sentence: Sending crafted web requests to the Salt API, with the SSH client enabled, can result in shell injection.
- Product mapping: saltstack salt (saltstack:salt)
- Confusers: CVE-2020-15415 [cwe], CVE-2020-1956 [cwe]
- Result: PASS ? human hand check completed.

## Q-0438
- Question: The affected product is apache flink; which CVE matches Apache Flink 1 5 1?
- Gold CVE: CVE-2020-17518
- Behaviour sentence: Apache Flink 1.5.1 introduced a REST handler that allows you to write an uploaded file to an arbitrary location on the local file system, through a maliciously modified HTTP HEADER.
- Product mapping: apache flink (apache:flink)
- Confusers: CVE-2020-5410 [cwe], CVE-2020-8195 [cwe]
- Result: PASS ? human hand check completed.

## Q-0476
- Question: Reviewing google chrome, which vulnerability is represented by Type confusion V8 Google Chrome?
- Gold CVE: CVE-2020-6418
- Behaviour sentence: Type confusion in V8 in Google Chrome prior to 80.0.3987.122 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.
- Product mapping: google chrome (google:chrome)
- Confusers: CVE-2020-16017 [vendor+product], CVE-2021-1789 [cwe]
- Result: PASS ? human hand check completed.

## Q-0522
- Question: Could you identify the exiftool project exiftool vulnerability described by Improper neutralization user data DjVu?
- Gold CVE: CVE-2021-22204
- Behaviour sentence: Improper neutralization of user data in the DjVu file format in ExifTool versions 7.44 and up allows arbitrary code execution when parsing the malicious image
- Product mapping: exiftool project exiftool (exiftool project:exiftool)
- Confusers: CVE-2022-22954 [cwe], CVE-2022-22963 [cwe]
- Result: PASS ? human hand check completed.

## Q-0527
- Question: Match ivanti connect secure to the CVE for the behavior Pulse Connect Secure 9 0R3.
- Gold CVE: CVE-2021-22893
- Behaviour sentence: Pulse Connect Secure 9.0R3/9.1R1 and higher is vulnerable to an authentication bypass vulnerability exposed by the Windows File Share Browser and Pulse Secure Collaboration features of Pulse Connect Secure that can allow an unauthenticated user to perform remote arbitrary code execution on the Pulse Connect Secure gateway.
- Product mapping: ivanti connect secure (ivanti:connect secure)
- Confusers: CVE-2021-1048 [cwe], CVE-2021-1905 [cwe]
- Result: PASS ? human hand check completed.

## Q-0557
- Question: When reviewing veritas backup exec, which CVE corresponds to using crafted input parameters one?
- Gold CVE: CVE-2021-27876
- Behaviour sentence: By using crafted input parameters in one of these commands, an attacker can access an arbitrary file on the system using System privileges.
- Product mapping: veritas backup exec (veritas:backup exec)
- Confusers: CVE-2021-27059 [cwe], CVE-2021-27085 [cwe]
- Result: PASS ? human hand check completed.

## Q-0630
- Question: The affected product is bqe billquick web suite; which CVE matches BQE BillQuick Web Suite 2018?
- Gold CVE: CVE-2021-42258
- Behaviour sentence: BQE BillQuick Web Suite 2018 through 2021 before 22.0.9.1 allows SQL injection for unauthenticated remote code execution, as exploited in the wild in October 2021 for ransomware installation.
- Product mapping: bqe billquick web suite (bqe:billquick web suite)
- Confusers: CVE-2021-45788 [cwe], CVE-2022-34265 [cwe]
- Result: PASS ? human hand check completed.

## Q-0677
- Question: What CVE should be assigned to apache apisix for the described case of attacker abuse batch-requests plugin send?
- Gold CVE: CVE-2022-24112
- Behaviour sentence: An attacker can abuse the batch-requests plugin to send requests to bypass the IP restriction of Admin API.
- Product mapping: apache apisix (apache:apisix)
- Confusers: CVE-2023-50224 [cwe], CVE-2024-4358 [cwe]
- Result: PASS ? human hand check completed.

## Q-0699
- Question: In a google chrome finding, what CVE is tied to Use after free Network Service?
- Gold CVE: CVE-2022-3038
- Behaviour sentence: Use after free in Network Service in Google Chrome prior to 105.0.5195.52 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.
- Product mapping: google chrome (google:chrome)
- Confusers: CVE-2021-30661 [cwe], CVE-2021-31166 [cwe]
- Result: PASS ? human hand check completed.
