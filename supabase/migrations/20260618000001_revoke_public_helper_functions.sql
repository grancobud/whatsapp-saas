-- Same PUBLIC-inheritance gap as 20260618000000, on the remaining
-- SECURITY DEFINER functions flagged by the Supabase security advisor
-- (lints 0028 anon_security_definer_function_executable and
-- 0029 authenticated_security_definer_function_executable).
--
-- Lower impact than the batch RPCs: the RLS helpers only answer about the
-- calling user (auth.uid()), and a trigger function cannot be invoked via RPC.
-- Still, anon has no business calling any of them.
--
--   auth_workspace_ids(), auth_has_role(), is_super_admin()
--     -> RLS policies evaluate them as the querying role, so `authenticated`
--        MUST keep EXECUTE. Revoke PUBLIC/anon only.
--   check_outbound_24h_window()
--     -> trigger function; EXECUTE is only checked at CREATE TRIGGER time, so
--        revoking it from every API role does not affect the trigger.

DO $$
BEGIN
  IF to_regprocedure('public.auth_workspace_ids()') IS NOT NULL THEN
    REVOKE ALL ON FUNCTION public.auth_workspace_ids() FROM PUBLIC, anon;
    GRANT EXECUTE ON FUNCTION public.auth_workspace_ids() TO authenticated, service_role;
  END IF;

  IF to_regprocedure('public.auth_has_role(uuid, public.workspace_role[])') IS NOT NULL THEN
    REVOKE ALL ON FUNCTION public.auth_has_role(uuid, public.workspace_role[]) FROM PUBLIC, anon;
    GRANT EXECUTE ON FUNCTION public.auth_has_role(uuid, public.workspace_role[]) TO authenticated, service_role;
  END IF;

  IF to_regprocedure('public.is_super_admin()') IS NOT NULL THEN
    REVOKE ALL ON FUNCTION public.is_super_admin() FROM PUBLIC, anon;
    GRANT EXECUTE ON FUNCTION public.is_super_admin() TO authenticated, service_role;
  END IF;

  IF to_regprocedure('public.check_outbound_24h_window()') IS NOT NULL THEN
    REVOKE ALL ON FUNCTION public.check_outbound_24h_window() FROM PUBLIC, anon, authenticated;
  END IF;
END
$$;
