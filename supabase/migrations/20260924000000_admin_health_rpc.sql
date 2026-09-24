-- Admin health snapshot for operators (used by the whatsapp-saas MCP).
--
-- cron.* and net.* are not exposed through PostgREST, so this SECURITY DEFINER
-- function returns a read-only summary: scheduled jobs (without the command,
-- which embeds CRON_SECRET), the last cron runs and the last pg_net HTTP
-- responses. Callable by service_role only.

CREATE OR REPLACE FUNCTION public.wsaas_admin_health()
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT jsonb_build_object(
    'jobs', (
      SELECT coalesce(jsonb_agg(jsonb_build_object(
        'jobid', j.jobid, 'name', j.jobname,
        'schedule', j.schedule, 'active', j.active)), '[]'::jsonb)
      FROM cron.job j
    ),
    'last_runs', (
      SELECT coalesce(jsonb_agg(r), '[]'::jsonb) FROM (
        SELECT d.jobid, d.status, left(d.return_message, 120) AS message, d.start_time
        FROM cron.job_run_details d
        ORDER BY d.start_time DESC LIMIT 5
      ) r
    ),
    'last_http', (
      SELECT coalesce(jsonb_agg(h), '[]'::jsonb) FROM (
        SELECT n.status_code, left(n.content, 160) AS content, n.error_msg, n.created
        FROM net._http_response n
        ORDER BY n.created DESC LIMIT 5
      ) h
    )
  );
$$;

REVOKE ALL ON FUNCTION public.wsaas_admin_health() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.wsaas_admin_health() TO service_role;
