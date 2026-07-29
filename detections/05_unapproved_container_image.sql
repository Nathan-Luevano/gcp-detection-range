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
WHERE action LIKE 'io.k8s.core.v1.pods.create%.unapproved_image'
