SELECT
  timestamp,
  actor,
  actor_type,
  source_ip,
  action,
  resource,
  resource_type,
  outcome
FROM `detection_range_test.normalized_events`
WHERE actor_type = 'service_account'
  AND NOT NET.IP_IN_NET(source_ip, '10.10.0.0/20')
