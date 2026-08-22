# What Is Splunk?
Splunk is a platform used to collect, search, monitor, analyze, and visualize machine generated data such as logs and events.

In cybersecurity, Splunk can be used for security monitoring, threat detection, log analysis, and incident investigation.
### Common Uses of Splunk
- **Log Management** — Collect and organize data from different systems, applications, and devices.
- **Search & Analysis** — Search large volumes of machine-generated data and investigate events.
- **Security Monitoring** — Monitor systems, users, applications, and network activity.
- **Threat Detection** — Identify patterns and activity that may indicate security threats.
- **Incident Investigation** — Analyze events and timelines during security investigations.
- **Visualization** — Present data using charts, dashboards, and reports.
- **Alerting** — Generate alerts when searches identify specific conditions.
### Basic Splunk Workflow
**Collect → Index → Search → Analyze → Monitor → Investigate**
1. **Collect** — Splunk receives data from different sources.
2. **Index** — Data is processed and stored so that it can be searched.
3. **Search** — Analysts search the data using SPL.
4. **Analyze** — Search results are examined for useful or suspicious activity.
5. **Monitor** — Dashboards and alerts can be used to monitor activity.
6. **Investigate** — Analysts examine relevant events when investigating an incident.
# What Is SPL?
**SPL** stands for **Search Processing Language**. It is the search language used in Splunk to search, filter, transform, analyze, and visualize data. Splunk's Search Reference provides the syntax and usage of SPL search commands.
### Basic SPL Structure
```spl
search | command | command
```
Example:
```spl
index=main error | stats count by host
```
This search:


**1.** Searches the `main` index for events containing `error`.

**2.** Passes the results to the `stats` command.

**3.** Counts the matching events.

**4.** Group the results by `host`.
### Important SPL Components

- **Search terms** — Words or phrases used to find matching events.

- **Fields** — Named pieces of information contained in events.

- **Commands** — Instructions that process or transform search results.

- **Functions** — Built-in operations used by commands.

- **Operators** — Used to compare or combine values.

- **Pipe** `|` — Passes the results of one command to the next command.

