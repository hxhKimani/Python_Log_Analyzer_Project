# Authentication log analysis

Rule matches are investigation leads; they do not establish compromise.

## Summary

- Valid Events: 12
- Failed Logins: 9
- Successful Logins: 3
- Unique Source Ips: 3
- Alert Count: 3
- Rejected Records: 0

## Settings

```json
{
  "failure_threshold": 5,
  "user_threshold": 3,
  "window_seconds": 300
}
```

## Alerts

```json
{
  "rule": "REPEATED_FAILURES",
  "timestamp": "2026-11-17T14:03:00+00:00",
  "source_ip": "203.0.113.50",
  "username": "admin",
  "evidence_lines": [
    3,
    4,
    5,
    6,
    7
  ],
  "failure_count": 5,
  "distinct_users": [
    "admin"
  ]
}
```

```json
{
  "rule": "SUCCESS_AFTER_FAILURES",
  "timestamp": "2026-11-17T14:03:30+00:00",
  "source_ip": "203.0.113.50",
  "username": "admin",
  "evidence_lines": [
    3,
    4,
    5,
    6,
    7
  ],
  "failure_count": 5,
  "distinct_users": [
    "admin"
  ]
}
```

```json
{
  "rule": "MULTIPLE_ACCOUNTS_TARGETED",
  "timestamp": "2026-11-17T14:04:40+00:00",
  "source_ip": "198.51.100.20",
  "username": "taylor",
  "evidence_lines": [
    9,
    10,
    11
  ],
  "failure_count": 3,
  "distinct_users": [
    "alex",
    "jordan",
    "taylor"
  ]
}
```


## Rejected records

```json
[]
```
