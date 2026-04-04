---- MODULE MC_Rotation ----
\* Model constants for Apalache model checking.
\*
\* N=4, f=1 — smallest non-trivial BFT configuration.
\*
\* Run: apalache-mc check --config=Rotation.cfg MC_Rotation.tla

EXTENDS Rotation

\* Model constants
MC_Validators == {"v1", "v2", "v3", "v4"}
MC_Byzantine == {"v4"}
MC_MaxRounds == 5

====
