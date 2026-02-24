Link environment files from the main repository into a git worktree so it can run with the same configuration.

## Steps

1. Determine the main repo root by running `git -C "$ARGUMENTS" worktree list` and finding the entry marked `(bare)` or the first entry (the main worktree).

2. Determine the worktree root. If `$ARGUMENTS` is provided, use it. Otherwise, use the current working directory.

3. Find all `.env*` files in the main repo (excluding `node_modules`, `.git`, `venv`, `.venv`, `__pycache__`):
   ```
   find <main-repo> -name ".env*" -not -path "*/node_modules/*" -not -path "*/.git/*" -not -path "*/venv/*" -not -path "*/.venv/*" -not -path "*/__pycache__/*"
   ```

4. For each `.env*` file found:
   - Compute its path relative to the main repo root
   - Check if that relative path already exists in the worktree
   - If it doesn't exist (or exists but isn't a symlink), create a symlink:
     ```
     ln -sf <main-repo>/<relative-path> <worktree>/<relative-path>
     ```
   - If it already exists as a symlink pointing to the right target, skip it

5. Report what was linked, what was skipped, and any errors.

## Important
- NEVER read or print the contents of `.env` files -- they contain secrets
- Only create symlinks, never copy files
- If a real `.env` file already exists in the worktree (not a symlink), warn the user and skip it rather than overwriting
- Use `ln -sf` for symlink creation
