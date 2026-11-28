Fixed
- Startup no longer aborts on a retained geodata schedule with no future occurrence in the local zone; it only warns and the update loop keeps its retry backoff. The API still rejects a newly submitted explicit cron with no future occurrence.
