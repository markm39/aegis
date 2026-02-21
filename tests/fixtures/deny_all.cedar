// Deny-all Cedar policy for testing.
//
// This is the most restrictive policy: every action by every principal
// on every resource is denied. Tests that need permissive behavior
// should use a different policy file.
forbid(principal, action, resource);
