# Present the project honestly

Complete the walkthrough, run the experiments, and implement an improvement before
presenting this as work you can independently explain. Getting assistance is normal;
claim the parts you actually understand and completed. Do not list it as employment
or claim production incident response experience.

## Resume entry (after completing the project)

**Python Authentication Log Analyzer | Personal Cybersecurity Project**

- Developed a Python command-line tool to validate and analyze authentication CSV
  logs, normalize timestamps, and summarize login activity by source IP.
- Implemented configurable sliding-window rules for repeated login failures,
  multiple-account targeting, and successful logins following repeated failures.
- Generated JSON and Markdown reports with source-row evidence and validated
  detection behavior with automated tests and synthetic authentication scenarios.

Adjust “Developed” to reflect your contribution if you only ran the supplied code.
Add your own improvement as a bullet once implemented. Do not claim real attacks
detected, reduced response times, or other measured outcomes without evidence.

## Interview explanation

“I built a portfolio project to practice authentication log analysis in Python.
It validates a defined CSV schema, normalizes timestamps to UTC, and sorts events.
I use sliding windows to identify repeated failures from a source and correlate
successful logins with prior failures for the same account. Reports include source
line numbers so I can trace findings. I tested it with synthetic scenarios, including
time boundaries and out-of-order records. The rules identify patterns for review;
they do not prove an account was compromised.”

Use this wording only after you can explain the implementation. Be transparent
about assistance if asked. Describe the improvement you implemented yourself.

## Questions to practice

1. Why use a Counter, deque, dictionary, set, and dataclass?
2. Why sort logs and normalize timezones before detection?
3. What changes if logs contain duplicates or several hosts behind one IP?
4. Why can this tool suggest, but not confirm, password spraying?
5. Why does a successful login reset a user's failure sequence?
6. What is lost by emitting only the first failure alert per IP per run?
7. How would you test a new distributed-account-targeting rule?
8. How would you adapt the program for data too large to fit in memory?
