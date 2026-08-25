# *A Curated Reference of Essential SPL Queries for SOC Analysts & Defensive Security.*
### Basic Searching, Filtering & Scope Bounding 
**1. Search Across Primary Security Indexes**
```
index=main OR index=security OR index=winlog
```
*Restricts search scope to main security repositories rather than querying all indexes.*

**2. Filter Windows Security Event Logs**
```
index=winlog sourcetype="XmlWinEventLog:Security" EventCode=4625
```
*Targets failed logon attempts specifically within normalized Windows Security logs.*

**3. Search Threat Keywords in Web Logs**
```
index=web_proxy "sqlmap" OR "select" OR "union"
```
*Scans proxy and web server logs for common web application attack vectors and tools.*

**4. Filter by Specific Compromised Target Host**
```
index=security dest="Executive-PC"
```
*Isolates telemetry related to a single affected endpoint during triage.*

**5. Exclude Known Administrative Noise**
```
index=security EventCode=4625 NOT (src_ip="0.0.0.0")
```
*Removes known false positives caused by vulnerability scanners or admin jump boxes.*
### Data Processing & Field Extraction
**6. Select Essential Fields to Speed up Sarches**
```
index=security | fields + _time, src_ip, dest_ip, user, action
```
*Drops unused event metadata early in the search pipeline to speed up search performance.*

**7. Format Results into a Clean Investigation Table:**
```
index=winlog EventCode=4625 | table _time, user, src_ip, dest
```
*Formats raw log output into clean readable columns for incident report timelines.*

**8. Rename Field Names to Standard Terminology:**
```
index=winlog | rename Account_Name AS user, Workstation_Name AS src
```
*Standardizes field names to align with Common Information Model (CIM) guidelines.*

**9. Calculate Data Transfer Size in Megabytes:**
```
index=netfirewall | eval total_mb=bytes/1024/1024 | where total_mb > 100
```
*Uses `eval` to compute file sizes and filters for data transfers exceeding 100 MB.*

**10. Extract Custom Fields Using Regex ( rex ):**
```
index=winlog EventCode=4688 | rex field=CommandLine "-enc\s+(?<encoded_args>[A-Za-z0-9+/=]+)"
```
*Extracts Base64 encoded command arguments into a standalone field named `encoded_args`.*

### Statistical Aggregations & Metrics(`stats`) 
**11. Count Total Events Per Log Source:**
```
index=main OR index=winlog | stats count by sourcetype
```
*Provides operational visibility into active logging sources across the network.*

**12. Identify top targeted accounts by failed login attempts**
```
index=winlog EventCode=4625 | stats count by user | sort -count
```
*Ranks user accounts experiencing the highest volume of authentication failures.*

**13. Detect Potential Password Spraying Attacks:**
```
index=winlog EventCode=4625 | stats dc(user) AS unique_targets by src_ip | where unique_targets >= 5
```
*Counts distinct usernames targeted by single source IP address.*

**14. Detect Potential Port Scanning Activity:**
```
index=netflow action=blocked | stats dc(dest_port) AS scanned_ports by src_ip | sort - scanned_ports
```
*Counts unique destination ports probed by a single external or internal IP.*

**15. Group All Hosts Accessed by a Specific User:**
```
index=security action=success | stats values(dest) AS accessed_hosts by user
```
*Consolidates all unique systems accessed by an account into a single multi-value list.*

**16. Calculate Threat Activity Time Duration:**
```
index=security user="attacker_account" | stats min(_time) AS first_seen, max(_time) AS last_seen | eval duration_min=(last_seen-first_seen)/60
```
*Determines the exact timeframe between an attacker's first and last observed actions.*

### Ranking, Visualization & Time-Series ( `timechart` )
**17. Identify Top 10 Blocked External IP Addresses:**
```
index=netfirewall action=blocked | stats count by src_ip | sort -count | head 10
```
*Extracts the top 10 most frequently dropped source IP addresses.*

**18. Find Rare Binary Executions Across Endpoints**
```
index=winlog EventCode=4688 | rare limit=10 NewProcessName
```
*Identifies unusual or low-frequency process paths executed across network hosts.*

**19. Graph Authentication Failures Over Time:**
```
index=winlog EventCode=4625 | timechart span=1h count BY dest
```
*Displays a hourly time-series line graph of failed logins split by target system.*

**20. Track High-Severity Alert Volume:**
```
index=security severity=high | timechart span=30m count
```
*Plots spikes in high-severity alerts in 30-minute intervals for visual dashboards.*


