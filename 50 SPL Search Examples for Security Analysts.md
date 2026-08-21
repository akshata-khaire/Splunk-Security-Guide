# *A security-focused guide to Splunk for SOC analysts and defensive security operations.*
### Basic Searching & Filtering
1. `index=*` - Search events across all indexes you have permission to access.
2. `index=main` - Search for events in the `main` index.
3. `index=main sourcetype=syslog` - Search the `main` index for events with the `syslog` sourcetype.
4. `index=main error` - Search the `main` index for events containing the term error.
5. `index=main "failed login"` - Search the main index for events containing the exact phrase `failed login`.
6. `index=main host=server01` - Search the `main` index for events from the specified hosts.
7. `index=main source="/var/log/auth.log/"` - Search the `main` index for events from the specified source.
8. `index=main status=404` - Search the `main` index for events where the `status` field is `404`.
9. `index=main earliest=-24h` - Search the `main` index for events from the last 24 hours.
10. `index=main earliest=-7d latest=now` - Search the `main` index for events from the last seven days.
### Field & Event Processing
11. `index=main | fields host, source, sourcetype` - Keep only the specified fields in the search results.
12. `index=main | table _time, host, source` - Display selected fields in a table.
13. `index=main | rename host AS hostname - Rename the `host` field to `hostname`.
14. `index=main | eval severity="High"` - Create a new field named `severity` with value `High`.
15. `index=main | eval total_bytes=bytes_in+bytes_out` - Create a calculated field by adding two numeric fields.
16. `index=main | where status=404` - Keep only results where the `status` field equals `404`.
17. `index=main | search error` - Filter the results for events containing the term `error`.
18. `index=main | rex "user=(?<username>\w+)"` - Extract a `username` field from matching raw event text using a regular expression.
19. `index=main | dedup user` - Remove duplicate results based on the `user` field.
20. `index=main | sort -_time` - Sort the results by _time in descending order.
### Event Statistics & Investigation
21. `index=main | stats count` - Count the number of matching events.
22. `index=main | stats count by host` - Count events for each host.
23. `index=main | stats count by user` - Count events for each user.
24. `index=main | stats count by source` - Count events for each source.
25. `index=main | stats count by sourcetype` - Count events for each sourcetype.
26. `index=main | stats dc(user) AS unique_users` - Count the distinct values of the `user` field.
27. `index=main | stats dc(src_ip) AS unique_ips` - Count the distinct values of the `src_ip` field.
28. `index=main | stats values(user) AS users` - Return the distinct values found in the `user` field.
29. `index=main | stats earliest(_time) AS first_event latest(_time) AS last_event` - Find the earliest and latest event times.
30. `index=main | stats avg(bytes) AS average_bytes` - Calculate the average value of the `bytes` field.
### Sorting, Ranking & Time Analysis
31. `index=main | stats count BY status | sort -count` - Count events by status and sort the results from highest to lowest count.
32. `index=main | head 10` - Return the first 10 results.
33. `index=main | tail 10` - Return the last 10 results.
34. `index=main | top user` - Display the most frequently occurring values of the `user` field.
35. `index=main | rare user` - Display the least frequently occurring values of the `user` field.
36. `index=main | chart count BY host` - Generate event counts grouped by host.
37. `index=main | timechart count` - Generate an event-count time series.
38. `index=main | timechart count BY host` - Generate an event-count time series grouped by host.
39. `index=main | stats count BY user | sort -count | head 10` - Display the 10 users with the highest event counts.
40. `index=main | bin _time span=1h | stats count BY _time` - Group events into one-hour time buckets and count them.
### Security & SOC Analysis
41. `index=main "failed" | stats count BY user` - Count events containing `failed`, grouped by user.
42. `index=main "failed" | stats count BY src_ip` - Count events containing `failed`, grouped by source IP.
43. `index=main | stats count BY src_ip | sort -count` - Rank source IP addresses by their number of events.
44. `index=main | stats count BY user, src_ip | sort -count` - Count events for each user and source IP combination.
45. `index=main | stats count BY host, user | sort -count` - Count events for each host and user combination.
46. `index=main | timechart count BY status` - Show event counts by status over time.
47. `index=main | stats count BY user | where count > 10` - Identify users associated with more than 10 matching events.
48. `index=main | stats dc(src_ip) AS unique_ips BY user | sort -unique_ips` - Rank users by the number of distinct source IP addresses associated with their event.
49. `index=main | bin _time span=1h | stats count BY _time, user` - Count events for each user in one hour time buckets.
50. `index=main | stats count BY sourcetype | sort -count` - Rank sourcetypes by their number of events.

*These SPL examples are intended for learning, security monitoring, and authorized analysis. Always use Splunk and security data responsibly and follow applicable laws, policies, and organizational guidelines.*
