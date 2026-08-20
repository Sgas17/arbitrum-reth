# Repository Agent Instructions

- Use hard cutovers only; do not add compatibility layers or legacy paths.
- Keep every change strictly scoped to the approved issue.
- Do not read or create secrets, credentials, or operator environment files.
- Do not access live nodes or RPCs, sync chains, deploy, push, open or merge pull requests, mutate Linear, or otherwise mutate external systems.
- During task execution, use dependencies prepared by Orb setup and run the issue's focused validation.
- Before stopping, create one cohesive local Orb commit and leave the worktree clean.
