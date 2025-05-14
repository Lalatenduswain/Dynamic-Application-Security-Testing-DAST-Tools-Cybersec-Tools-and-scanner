# Dynamic Application Security Testing (DAST) Tools

*(Focused on Web Applications)*

A continually maintained and community-driven collection of outstanding resources, tools, best practices, libraries, frameworks, eBooks, videos, blog posts, GitHub repositories, and technical guidelines related to **Dynamic Application Security Testing (DAST)**.

> **Shout-out to all contributors** – your efforts make this possible! This initiative aims to provide a well-organized, categorized reference for professionals seeking reliable DAST-related resources.

---

## 🔍 What is Dynamic Application Security Testing (DAST)?

**Dynamic Application Security Testing (DAST)** refers to a category of security testing tools designed to scan running web applications for vulnerabilities. These tools interact with your application in real-time, simulating an attacker’s behavior to identify issues such as:

* Cross-Site Scripting (XSS)
* SQL Injection
* Command Injection
* Path Traversal
* Insecure Server Configurations

DAST tools operate without access to the underlying source code, making them ideal for black-box testing approaches in pre-production or staging environments.

---

## 🛡️ OWASP & Vulnerability Scanning Tools

DAST tools, often referred to as **Web Application Vulnerability Scanners**, play a crucial role in application security. These tools scan deployed web apps from the outside, aiming to identify exploitable vulnerabilities before attackers do.

There are many open-source and commercial DAST tools available, each with distinct features and capabilities. To evaluate the efficacy of such tools, refer to the **[OWASP Benchmark Project](https://owasp.org/www-project-benchmark/)**—a scientific initiative that measures and compares the detection capabilities of various security scanners, including DAST.

### ⚠️ Disclaimer

* The tools listed are presented in **alphabetical order**.
* **OWASP does not endorse** any particular vendor or tool by listing them.
* The **Web Application Vulnerability Scanner Evaluation Project (WAVSEP)** is an independent project and **not affiliated with OWASP**. While OWASP does not endorse WAVSEP or its findings, the data may still be valuable for comparing the functionality and accuracy of both free and commercial scanners.

---

|                    Name/Link                    |         Owner         |       License       |              Platforms              |                                                                         Note                                                                        |
|:-----------------------------------------------:|:---------------------:|:-------------------:|:-----------------------------------:|:---------------------------------------------------------------------------------------------------------------------------------------------------:|
| [Abbey Scan](https://misterscanner.com/)                                      | MisterScanner         | Commercial          | SaaS                                |                                                                                                                                                     |
| [Acunetix](https://www.acunetix.com/)                                       | Acunetix              | Commercial          | Windows, Linux, MacOS               | Free (Limited Capability)                                                                                                                           |
| [APIsec](https://www.apisec.ai/free-api-pen-test)                                          | APIsec                | Commercial          | SaaS                                | Free limited API Pen Test                                                                                                                           |
| [App Scanner](https://www.trustwave.com/en-us/services/penetration-testing/)                                     | Trustwave             | Commercial          | Windows                             |                                                                                                                                                     |
| [AppCheck Ltd.](https://appcheck-ng.com/)                                   | AppCheck Ltd.         | Commercial          | SaaS                                | Free trial scan available                                                                                                                           |
| [AppScan](https://www.hcltechsw.com/appscan)                                         | HCL Software          | Commercial          | Windows                             |                                                                                                                                                     |
| [AppScan on Cloud](https://cloud.appscan.com/)                                | HCL Software          | Commercial          | SaaS                                |                                                                                                                                                     |
| [AppSpider](https://www.rapid7.com/products/appspider/)                                       | Rapid7                | Commercial          | Windows                             |                                                                                                                                                     |
| [AppTrana Website Security Scan](https://apptrana.indusface.com/basic/)                  | AppTrana              | Free                | SaaS                                |                                                                                                                                                     |
| [Arachni](https://www.arachni-scanner.com/)                                         | Arachni               | Free                | Most platforms supported            | Free for most use cases                                                                                                                             |
| [Astra Security Suite](https://www.getastra.com/)                            | Astra Security        | Free                | SaaS                                | Paid Option Available                                                                                                                               |
| [Beagle Security](https://beaglesecurity.com/)                                 | Beagle Security       | Commercial          | SaaS                                | Free (Limited Capability)                                                                                                                           |
| [beSECURE (formerly AVDS)](https://beyondsecurity.com/)                        | Beyond Security       | Commercial          | SaaS                                | Free (Limited Capability)                                                                                                                           |
| [BlueClosure BC Detect](https://www.blueclosure.com/)                           | BlueClosure           | Commercial          | Most platforms supported            | 2 week trial                                                                                                                                        |
| [BREACHLOCK Dynamic Application Security Testing](https://www.breachlock.com/dynamic-application-security-testing/) | BREACHLOCK            | Commercial          | SaaS                                |                                                                                                                                                     |
| [Burp Suite](https://portswigger.net/)                                      | PortSwiger            | Commercial          | Most platforms supported            | Free (Limited Capability)                                                                                                                           |
| [CloudDefense](https://www.clouddefense.ai/)                                    | CloudDefense          | Commercial          | SaaS or On-Premises                 | CloudDefense DAST integrates with any CI/CD with just 1 line of code. It supports multiple authentication types. Perform deep DAST scans with ease. |
| Contrast                                        | Contrast Security     | Commercial          | SaaS or On-Premises                 | Free (Full featured for 1 App)                                                                                                                      |
| Crashtest Security                              | Crashtest Security    | Commercial          | SaaS or On-Premises                 |                                                                                                                                                     |
| Cyber Chief                                     | Audacix               | Commercial          | SaaS or On-Premises                 |                                                                                                                                                     |
| Deepfence ThreatMapper                          | Deepfence             | Open Source         | Linux                               | Apache v2                                                                                                                                           |
| Deepfence ThreatStryker                         | Deepfence             | Commercial          | Linux, Windows                      |                                                                                                                                                     |
| Detectify                                       | Detectify             | Commercial          | SaaS                                |                                                                                                                                                     |
| Digifort- Inspect                               | Digifort              | Commercial          | SaaS                                |                                                                                                                                                     |
| Edgescan                                        | Edgescan              | Commercial          | SaaS                                |                                                                                                                                                     |
| GamaScan                                        | GamaSec               | Commercial          | Windows                             |                                                                                                                                                     |
| GoLismero                                       | GoLismero Team        | Open Source         | Windows, Linux and Macintosh        | GPLv2.0                                                                                                                                             |
| Grabber                                         | Romain Gaucher        | Open Source         | Python 2.4, BeautifulSoup and PyXML |                                                                                                                                                     |
| Grendel-Scan                                    | David Byrne           | Open Source         | Windows, Linux and Macintosh        |                                                                                                                                                     |
| HostedScan.com                                  | HostedScan.com        | Commercial          | SaaS                                | Free Forever                                                                                                                                        |
| IKare                                           | ITrust                | Commercial          | N/A                                 |                                                                                                                                                     |
| ImmuniWeb                                       | High-Tech Bridge      | Commercial          | SaaS                                | Free (Limited Capability)                                                                                                                           |
| Indusface Web Application Scanning              | Indusface             | Commercial          | SaaS                                | Free trial available                                                                                                                                |
| InsightVM                                       | Rapid7                | Commercial          | SaaS                                | Free trial available                                                                                                                                |
| Intruder                                        | Intruder Ltd.         | Commercial          |                                     |                                                                                                                                                     |
| IOTHREAT                                        | IOTHREAT              | Commercial          | SaaS                                | Free (View Partial Results). Full report (PRO) - 50% discount for the OWASP community with 'OWASP50'.                                               |
| K2 Security Platform                            | K2 Cyber Security     | Commercial          | SaaS/On-Premise                     | Free trial available                                                                                                                                |
| Mayhem for API                                  | ForAllSecure          | Commercial          | SaaS                                | 30-day Free Trial                                                                                                                                   |
| N-Stealth                                       | N-Stalker             | Commercial          | Windows                             |                                                                                                                                                     |
| Nessus                                          | Tenable               | Commercial          | Windows                             |                                                                                                                                                     |
| Netsparker                                      | Netsparker            | Commercial          | Windows                             |                                                                                                                                                     |
| Nexploit                                        | NeuraLegion           | Commercial          | SaaS                                |                                                                                                                                                     |
| Nexpose                                         | Rapid7                | Commercial          | Windows/Linux                       | Free (Limited Capability)                                                                                                                           |
| Nikto                                           | CIRT                  | Open Source         | Unix/Linux                          |                                                                                                                                                     |
| Nmmapper Tool Collections                       | Nmmapper              | Commercial          | SasS                                | Great Collection of Kali Tool hosted online                                                                                                         |
| Nuclei                                          | ProjectDiscovery      | Open Source         | Windows, Unix/Linux, and Macintosh  | Fast and customisable vulnerability scanner based on simple YAML based DSL.                                                                         |
| OpenVAS by Greenbone                            | greenbone             | Open Source         | Linux                               | Open source full-featured vulnerability scanner, developed and maintained by Greenbone Networks GmbH.                                               |
| Probely                                         | Probely               | Commercial          | SaaS                                | Free (Limited Capability)                                                                                                                           |
| Proxy.app                                       | Websecurify           | Commercial          | Macintosh                           |                                                                                                                                                     |
| purpleteam                                      | OWASP                 | Open Source         | CLI and SaaS                        | GNU-AGPL v3                                                                                                                                         |
| QualysGuard                                     | Qualys                | Commercial          | N/A                                 |                                                                                                                                                     |
| ReconwithMe                                     | Nassec                | Commercial          | SaaS                                | Paid Option Available                                                                                                                               |
| Retina                                          | BeyondTrust           | Commercial          | Windows                             |                                                                                                                                                     |
| Ride (REST JSON Payload fuzzer)                 | Adobe, Inc.           | Open Source         | Linux / Mac / Windows               | Apache 2                                                                                                                                            |
| ScanRepeat                                      | Ventures CDX          | Commercial          | SaaS                                |                                                                                                                                                     |
| ScanTitan Vulnerability Scanner                 | ScanTitan             | Commercial          | SaaS                                | Free (Limited Capability)                                                                                                                           |
| Sec-helpers                                     | VWT Digital           | Open Source or Free | N/A                                 |                                                                                                                                                     |
| SecPoint Penetrator                             | SecPoint              | Commercial          | N/A                                 |                                                                                                                                                     |
| Security For Everyone                           | Security For Everyone | Commercial          | SaaS                                | Free (Limited Capability)                                                                                                                           |
| Securus                                         | Orvant, Inc           | Commercial          | N/A                                 |                                                                                                                                                     |
| Sentinel                                        | WhiteHat Security     | Commercial          | N/A                                 |                                                                                                                                                     |
| SmartScanner                                    | SmartScanner          | Commercial          | Windows                             | Free (Limited Capability)                                                                                                                           |
| SOATest                                         | Parasoft              | Commercial          | Windows / Linux / Solaris           |                                                                                                                                                     |
| StackHawk                                       | StackHawk             | Commercial          | SaaS                                |                                                                                                                                                     |
| Tinfoil Security                                | Synopsys              | Commercial          | SaaS or On-Premises                 | Free (Limited Capability)                                                                                                                           |
| Trustkeeper Scanner                             | Trustwave SpiderLabs  | Commercial          | SaaS                                |                                                                                                                                                     |
| Vega                                            | Subgraph              | Open Source         | Windows, Linux and Macintosh        |                                                                                                                                                     |
| Vex                                             | UBsecure              | Commercial          | Windows                             |                                                                                                                                                     |
| w3af                                            | w3af.org              | Open Source         | Linux and Mac                       | GPLv2.0                                                                                                                                             |
| Wapiti                                          | Informática Gesfor    | Open Source         | Windows, Unix/Linux and Macintosh   |                                                                                                                                                     |
| Web Security Scanner                            | DefenseCode           | Commercial          | On-Premises                         |                                                                                                                                                     |
| WebApp360                                       | TripWire              | Commercial          | Windows                             |                                                                                                                                                     |
| WebCookies                                      | WebCookies            | Free                | SaaS                                |                                                                                                                                                     |
| [WebInspect](https://www.microfocus.com/en-us/cyberres/application-security/webinspect)                                      | Micro Focus           | Commercial          | Windows                             |                                                                                                                                                     |
| WebReaver                                       | Websecurify           | Commercial          | Macintosh                           |                                                                                                                                                     |
| WebScanService                                  | German Web Security   | Commercial          | N/A                                 |                                                                                                                                                     |
| [Websecurify Suite](https://suite.websecurify.com/)                               | Websecurify           | Commercial          | Windows, Linux, Macintosh           | Free (Limited Capability)                                                                                                                           |
| [Website Security Check](https://cyberant.com/en/website-security-check/)                          | CyberAnt              | Commercial          | SaaS                                | 20% off with OWASP20                                                                                                                                |
| [WPScan](https://wpscan.com/wordpress-security-scanner/)                                          | WPScan Team           | Commercial          | Linux and Mac                       | Free options                                                                                                                                        |
| [Zed Attack Proxy](https://www.zaproxy.org/)                                | OWASP                 | Open Source         | Windows, Unix/Linux, and Macintosh  | Apache-2.0                                                                                                                                          |



# 🛡️ Cyber Security Toolkit Scanner

A comprehensive collection of essential cybersecurity tools, platforms, practice labs, and open-source utilities. This project helps ethical hackers, security engineers, and infosec learners quickly access all the top-rated platforms and scanners via a central reference.

📁 **Repo:** [https://github.com/Lalatenduswain/cybersec-tools-scanner](https://github.com/Lalatenduswain/cybersec-tools-scanner)

---

## 📌 Features

- 🚀 Centralized access to 60+ cybersecurity tools
- 📚 Direct links to practice labs (HTB, TryHackMe, VulnHub, etc.)
- 🔒 Password crackers, reverse engineering, red teaming kits
- 🧠 Threat intelligence, CVE databases, malware sandboxes
- 🌐 Easy to navigate and link-rich format for fast lookup

---

## 📖 Installation Guide

### ✅ Prerequisites

Ensure you have:
- Bash (v4 or later)
- Internet connectivity
- Tools like `curl` or `wget` (if you automate link usage)

### 🛠️ Quick Start

```bash
git clone https://github.com/Lalatenduswain/cybersec-tools-scanner.git
cd cybersec-tools-scanner
chmod +x cybersec-tools-scanner.sh
./cybersec-tools-scanner.sh
````

---

## 🧰 Tools Reference Table

| Tool Name                       | URL                                                                                                                                                                                   |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Acunetix                        | [https://cve.mitre.org/](https://cve.mitre.org/)                                                                                                                                      |
| Aircrack-ng                     | [https://overthewire.org/wargames/](https://overthewire.org/wargames/)                                                                                                                |
| BeEF                            | [https://github.com/commixproject/commix](https://github.com/commixproject/commix)                                                                                                    |
| Burpsuite                       | [https://www.cleancss.com/sha256-hash-generator/](https://www.cleancss.com/sha256-hash-generator/)                                                                                    |
| Cain and Abel                   | [https://nvd.nist.gov/](https://nvd.nist.gov/)                                                                                                                                        |
| Cobalt                          | [https://www.hackthebox.eu/](https://www.hackthebox.eu/)                                                                                                                              |
| EtterCap                        | [http://urlhaus.abuse.ch](http://urlhaus.abuse.ch)                                                                                                                                    |
| Forcepoint                      | [https://github.com/ChristianPapathanasiou/apache-rootkit](https://github.com/ChristianPapathanasiou/apache-rootkit)                                                                  |
| Hashcat                         | [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html)                                                                                              |
| Intruder                        | [https://shop.hak5.org/](https://shop.hak5.org/)                                                                                                                                      |
| jfrog                           | [https://tryhackme.com/](https://tryhackme.com/)                                                                                                                                      |
| John The Ripper                 | [http://threatfox.abuse.ch](http://threatfox.abuse.ch)                                                                                                                                |
| Kali                            | [https://en.wikipedia.org/wiki/List\_of\_file\_signatures](https://en.wikipedia.org/wiki/List_of_file_signatures)                                                                     |
| KeePass                         | [https://smallseotools.com/md5-generator/](https://smallseotools.com/md5-generator/)                                                                                                  |
| KisMAC                          | [https://github.com/n0kovo/awesome-password-cracking?tab=readme-ov-file](https://github.com/n0kovo/awesome-password-cracking?tab=readme-ov-file)                                      |
| MetaSploit                      | [http://pwnable.kr/](http://pwnable.kr/)                                                                                                                                              |
| Nagios                          | [http://yaraify.abuse.ch](http://yaraify.abuse.ch)                                                                                                                                    |
| Nessus                          | [https://www.md5hashgenerator.com/](https://www.md5hashgenerator.com/)                                                                                                                |
| NetStumbler                     | [https://ransomfeed.it/](https://ransomfeed.it/)                                                                                                                                      |
| Nexpose                         | [https://www.root-me.org/](https://www.root-me.org/)                                                                                                                                  |
| Nikto                           | [http://hybrid-analysis.com](http://hybrid-analysis.com)                                                                                                                              |
| NMap                            | [https://md5hashing.net/hash](https://md5hashing.net/hash)                                                                                                                            |
| Paros Proxy                     | [https://www.nomoreransom.org/crypto-sheriff.php](https://www.nomoreransom.org/crypto-sheriff.php)                                                                                    |
| POf                             | [https://ctflearn.com/](https://ctflearn.com/)                                                                                                                                        |
| Rapid7                          | [http://joesecurity.org](http://joesecurity.org)                                                                                                                                      |
| Snort                           | [http://onlinemd5.com/](http://onlinemd5.com/)                                                                                                                                        |
| Splunk                          | [https://github.com/yeyintminthuhtut/Awesome-Red-Teaming?tab=readme-ov-file](https://github.com/yeyintminthuhtut/Awesome-Red-Teaming?tab=readme-ov-file)                              |
| SQLMap                          | [https://www.vulnhub.com/](https://www.vulnhub.com/)                                                                                                                                  |
| Swagger                         | [https://any.run/](https://any.run/)                                                                                                                                                  |
| Tcpdump                         | [http://www.md5.cz/](http://www.md5.cz/)                                                                                                                                              |
| W3AF                            | [https://www.exterro.com/digital-forensics-software/ftk-imager](https://www.exterro.com/digital-forensics-software/ftk-imager)                                                        |
| Wire Shark                      | [https://www.hackthissite.org/](https://www.hackthissite.org/)                                                                                                                        |
| Zed Attack Proxy                | [http://virusshare.com](http://virusshare.com)                                                                                                                                        |
| OpenVAS                         | [https://emn178.github.io/online-tools/sha3\_512.html](https://emn178.github.io/online-tools/sha3_512.html)                                                                           |
| Qualys                          | [https://www.wechall.net/](https://www.wechall.net/)                                                                                                                                  |
| Tenable.io                      | [http://virustotal.com](http://virustotal.com)                                                                                                                                        |
| Retina Network Security Scanner | [https://10015.io/tools/md5-encrypt-decrypt](https://10015.io/tools/md5-encrypt-decrypt)                                                                                              |
| Tails                           | [https://cryptohack.org/](https://cryptohack.org/)                                                                                                                                    |
| PEStudio                        | [http://maltiverse.com](http://maltiverse.com)                                                                                                                                        |
| HexEditor                       | [https://NSATools.topsecret.link/qe9x8](https://NSATools.topsecret.link/qe9x8)                                                                                                        |
| ExeInfo                         | [https://lordofthesqli.stairwaytohell.com/](https://lordofthesqli.stairwaytohell.com/)                                                                                                |
| ProcessorHacker                 | [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com/)                                                                                                                  |
| HashCalculation                 | [https://cryptii.com/pipes/rot13-decoder](https://cryptii.com/pipes/rot13-decoder)                                                                                                    |
| CARO                            | [http://reversing.kr/](http://reversing.kr/)                                                                                                                                          |
| FLOSS                           | [https://www.devglan.com/online-tools/text-encryption-decryption](https://www.devglan.com/online-tools/text-encryption-decryption)                                                    |
| UTM (Unified Threat Management) | [https://microcorruption.com](https://microcorruption.com)                                                                                                                            |
| ProcMon                         | [https://underthewire.tech/wargames/](https://underthewire.tech/wargames/)                                                                                                            |
| Noriben                         | [https://www.dcode.fr/md5-hash](https://www.dcode.fr/md5-hash)                                                                                                                        |
| TCP View                        | [https://ctftime.org/](https://ctftime.org/)                                                                                                                                          |
| NGRock                          | [https://picoctf.org/](https://picoctf.org/)                                                                                                                                          |
| Cloudflare Tunnel               | [https://www.md5hashgenerator.com/](https://www.md5hashgenerator.com/)                                                                                                                |
| CashCat                         | [https://pentesterlab.com/](https://pentesterlab.com/)                                                                                                                                |
| Zabbix                          | [https://r3ds3ctor.github.io/red-team-guide/](https://r3ds3ctor.github.io/red-team-guide/)                                                                                            |
| knowbe4                         | [https://md5decrypt.net/en/](https://md5decrypt.net/en/)                                                                                                                              |
| DeepDarkCT                      | [http://tenable.io/](http://tenable.io/)                                                                                                                                              |
| Wazuh                           | [https://csrc.nist.gov/glossary/term/european\_institute\_for\_computer\_antivirus\_research](https://csrc.nist.gov/glossary/term/european_institute_for_computer_antivirus_research) |
| Netcat                          | [https://bit.ly/Cyber-Security-Tools](https://bit.ly/Cyber-Security-Tools)                                                                                                            |
| commix                          | [https://github.com/commixproject/commix](https://github.com/commixproject/commix)                                                                                                    |
| Apache Rootkit                  | [https://github.com/ChristianPapathanasiou/apache-rootkit](https://github.com/ChristianPapathanasiou/apache-rootkit)                                                                  |

---

## 💖 Support & Donations

If you find this useful:

* 🌐 Visit: [https://blog.lalatendu.info](https://blog.lalatendu.info)
* ⭐ Star this repo and share
* 📧 Feedback or ideas? Open a GitHub issue!

---

## ⚠️ Disclaimer

**Author:** Lalatendu Swain | [GitHub](https://github.com/Lalatenduswain) | [Website](https://blog.lalatendu.info)

This script and list are intended strictly for **educational and ethical research purposes**. Any misuse is strictly discouraged. The author is not responsible for misuse or damages.
## References
- SAST Tools - OWASP page with similar information on Static Application Security Testing (SAST) Tools
- Free for Open Source Application Security Tools - OWASP page that lists the Commercial Dynamic Application Security Testing (DAST) tools we know of that are free for Open Source
- http://sectooladdict.blogspot.com/ - Web Application Vulnerability Scanner Evaluation Project (WAVSEP)
- http://projects.webappsec.org/Web-Application-Security-Scanner-Evaluation-Criteria - v1.0 (2009)
- http://www.slideshare.net/lbsuto/accuracy-and-timecostsofwebappscanners - White Paper: Analyzing the Accuracy and Time Costs of WebApplication Security Scanners - By Larry Suto (2010)
- http://samate.nist.gov/index.php/Web_Application_Vulnerability_Scanners.html - NIST home page which links to: NIST Special Publication 500-269: Software Assurance Tools: Web Application Security Scanner Functional Specification Version 1.0 (21 August, 2007)
- http://www.softwareqatest.com/qatweb1.html#SECURITY - A list of Web Site Security Test Tools. (Has both DAST and SAST tools)


**[`^        back to top        ^`](#)**


## License

This work is licensed under the terms of the **MIT License** and the **Creative Commons Attribution 4.0 International License (CC BY 4.0)**.

<a rel="license" href="https://creativecommons.org/licenses/by/4.0/">
  <img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by/4.0/88x31.png" />
</a>  
<br />
This content is distributed under the  
<a rel="license" href="https://creativecommons.org/licenses/by/4.0/">Creative Commons Attribution 4.0 International License</a>.

To the fullest extent permitted by law,
[Lalatendu Swain](https://github.com/lalatenduswain/) has waived all copyrights and related rights to this work.
