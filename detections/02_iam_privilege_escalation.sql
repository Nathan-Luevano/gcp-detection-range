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
  AND action IN ('SetIamPolicy', 'GenerateAccessToken')
