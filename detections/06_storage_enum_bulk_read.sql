SELECT
  actor,
  actor_type,
  ANY_VALUE(source_ip) AS source_ip,
  TIMESTAMP_TRUNC(timestamp, HOUR) AS window_start,
  COUNT(*) AS object_read_count
FROM `detection_range_test.normalized_events`
WHERE action = 'storage.objects.get'
GROUP BY actor, actor_type, window_start
HAVING COUNT(*) >= 10
