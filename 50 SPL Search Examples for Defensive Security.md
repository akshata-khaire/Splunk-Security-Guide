# *A Security-Focused Guide to Splunk for SOC Analysts and Defensive Security Operations* 
### Basic Searching, Filtering & Scope Bounding
1. **Search across primary security indexes**:
   ```
   index=security OR index=winlog OR index=netfirewall
   ```
   
   Searches across defined security data stores rather than using performance-killing `index=*`.
2. **Target specific Windows event logs**:
   ```
   index=winlog sourcetype="XmlWinEventLog:Security"
   ```

   Restricts scope to normalized Windows Security Event Logs.
3. **Filter by Linux authentication events**:
   ```
   index=linux_auth sourcetype=syslog source="/var/log/auth.log"
   ```

   Proper exact file path matching without trailing slashes.
4. **Search for explicit threat keywords in web logs**:
   ```
   index=web_proxy"sqlmap" OR "select" OR "union"
   ```

   Searches raw payload/URI data for common web application attack strings.
5. **Locate failed authentication attempts**:
   ```
   index=security action=failure OR EventCode=4625
   ```

   Filters using field-value pairs rather than bare term searches.
6. **Filter by compromised destination host**:
   ```
   index=security dest="dc-01.corp.internal"
   ```

   Targets events affecting a specific critical host assets.
7. **Isolate specific HTTP status codes**:
   ```
   index=web_proxy status="403" OR status="500"
   ```

   Quotes numeric values treated as string fields in web proxy log models.
8. **Filter events bounded to the last 24 hours**:
   ```
   index=security earliest=-24h@h latest=now
   ```

   Explicitly sets index bucket time boundaries in SPL.
9. **Filter events bounded to a specific incident window**:
   ```
   index=security earliest="MM/DD/YYYY:00:00:00" latest="MM/DD/YYYY:00:00:00"
   ```

   Restricts search scope to an exact historical incident timeframe.
10. **Exclude trusted administrative hosts**:
   
    ```
    index=security EventCode=4625 NOT (src_ip="ADMIN_IP _1 OR src_ip="ADMIN_IP _2")
    ```

    Eliminates known false positives caused by vulnerability scanners or admin jump boxes.
### Field Extraction, Processing & Data Transformation
11. **Select specific CIM fields early to minimize memory footprint**: 
    ```
    index=security | fields + _time, src, dest, user, action, signature
    ```

    Drops unused event metadata early in the search pipeline.
12. **Format investigative output into a structured table**: 
    ```
    index=security action=failure | table _time, user, src, dest, signature
    ```
  
    Displays clean, tabular output for reporting and triage.
13. **Normalize legacy field names to CIM standards**: 
    ```
    index=winlog | rename Account_Name AS user, Workstation_Name AS src
    ```

    Aligns custom or non-standard field names with Splunk CIM guidelines.
14. **Create calculated risk impact levels**:
    ```
    index=security | eval risk_score=if(action=="failure", 50, 10)
    ```

    Dynamically calculates numerical risk scores based on event properties.
15. **Calculate total network bandwidth consumed**: 
    ```
    index=netfirewall | eval total_bytes=bytes_in + bytes_out
    ```

    Computes network volume per session.
16. **Filter results using `where` logic after extraction**: 
    ```
    index=netfirewall | eval total_mb=(bytes_in + bytes_out)/1024/1024 | where total_mb>500
    ```

    Isolates high-volume data transfers exceeding 500 MB.
17. **Filter raw log text matching specific string patterns**: 
    ```
    index=security "powershell.exe" | search "-EncodedCommand"
    ```

    Filters base search results for suspicious execution flags.
18. **Extract custom fields using regex (e.g., encoded command strings)**: 
    ```
    index=winlog EventCode=4688| rex field=CommandLine "-enc\s+(?<encoded_args>[A-Za-z0-9+/=]+)"
    ```

    Extracts Base64 payload strings into a readable field.
19. **Remove duplicate alerts while maintaining execution context**: 
    ```
    index=security signature="Brute Force Detected" | dedup src_ip, dest
    ```

    Limits noise by returning only the most recent unique source-destination alert pair.
20. **Sort events chronologically for timeline analysis**: 
    ```
    index=security user="jdoe" | sort 0 _time
    ```

    Ensures complete chronological ordering without truncation ( `sort 0` ).
### Event Aggregations & Threat Metrics
21. **Count total log volume per index**:
    ```
    index=security OR index=winlog OR index=netfirewall | stats count by index
    ```

    Provides baseline operational health metrics across security data sources.
22. **Identify top targeted systems by failed logon count**:  
    ```
    index=winlog EventCode=4625 | stats count by dest | sort - count
    ```

    Ranks destination systems experiencing the highest authentication failures.
23. **Summarize user activity across distinct hosts**:
    ```
    index=security action=failure | stats count by user | sort -count
    ```

    Aggregates login failures by targeted account.
24. **Group log sources generating security telemetry**:
    ```
    index=security | stats count by sourcetype
    ```

    Lists active sourcetypes within the security ecosystem.
25. **Measure distinct targeted accounts per source IP**:
    ```
    index=winlog EventCode=4625 | stats dc(user) AS unique_accounts by src_ip | where unique_accounts>5
    ```

    Detects potential password spraying attacks(one IP targeting many users).

26. **Measure distinct target hosts per source IP**:
    ```
    index=netflow action=blocked | stats dc(dest_ip) AS targeted_hosts by src_ip | sort - targeted_hosts
    ```

    Identifies internal or external network scanning activity.
27. **Aggregate distinct values into a single multivalued field**:
    ```
    index=security action=failure | stats values(dest) AS targeted_systems by user
    ```

    Lists all unique systems a compromised user attempted to access.
28. **Determine exact threat actvity duation**:
    ```
    index=security user="bwayne" | stats min(_time) AS first_seen, max(_time) AS last_seen | eval duration_min=(last_seen-first_seen)/60 | fieldformat first_seen=strftime(first_seen,"%Y-%m-%d%H:%M:%S")| fieldformat last_seen=strftime(last_seen,"%Y-%m-%d%H:%M:%S")
    ```

    Calculates the exact window of activity for a subject during investigation.
  

    
    

  
