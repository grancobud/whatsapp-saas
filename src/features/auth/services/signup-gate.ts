import { createClient as createSbClient } from "@supabase/supabase-js";

// ──────────────────────────────────────────────────────────────────────────────
// Signup gate — one-click-install bootstrap.
//
// Public self-registration is closed. The ONLY account that can self-register
// is the very first one (the agency super admin). Once any user exists, signup
// is closed and new people must be invited from the agency panel.
// ──────────────────────────────────────────────────────────────────────────────

function admin() {
  return createSbClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!,
  );
}

/**
 * Signup is open only while there are zero users (fresh install).
 * Counts auth.users, not public.users: a signUp() only creates the auth row,
 * so counting the profile table kept the gate open after the first signup.
 * Fails closed: any read error reports signup as closed.
 */
export async function isSignupOpen(): Promise<boolean> {
  const { data, error } = await admin().auth.admin.listUsers({
    page: 1,
    perPage: 1,
  });

  if (error) return false;
  return data.users.length === 0;
}

/**
 * Promotes the bootstrap user (first registration) to agency super admin.
 * Upserts the public.users profile: there is no signup trigger, so an UPDATE
 * alone matched zero rows and the first user ended up without a profile.
 */
export async function markAsSuperAdmin(
  userId: string,
  email: string,
): Promise<void> {
  await admin()
    .from("users")
    .upsert(
      {
        id: userId,
        email,
        full_name: email.split("@")[0],
        is_super_admin: true,
      },
      { onConflict: "id" },
    );
}
