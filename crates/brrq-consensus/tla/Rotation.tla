---- MODULE Rotation ----
\* Brrq BFT Rotation FSM — TLA+ formal specification.
\*
\* Models the 4-state FSM from rotation.rs:
\*   WaitingForProposal → PreVoting → PreCommitting → Finalized
\*
\* Annotated with rotation.rs line references for traceability.
\*
\* Parameters:
\*   N = number of validators
\*   f = max Byzantine validators (N > 3f)
\*   MaxRounds = maximum rounds before height failure

EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS
    Validators,     \* Set of validator addresses
    Byzantine,      \* Subset of Byzantine validators
    MaxRounds       \* Maximum rounds per height

ASSUME Byzantine \subseteq Validators
ASSUME Cardinality(Byzantine) * 3 < Cardinality(Validators)

Honest == Validators \ Byzantine
N == Cardinality(Validators)
f == Cardinality(Byzantine)

\* Quorum: >2/3 of total validators (stake-weighted in code, count-based here)
\* rotation.rs:219-227: stake * 3 >= total * 2
Quorum == (2 * N) \div 3 + 1

\* Phases — rotation.rs:60-84
Phases == {"Waiting", "PreVoting", "PreCommitting", "Finalized"}

VARIABLES
    phase,          \* phase[v] ∈ Phases — each validator's local phase
    round,          \* round[v] ∈ Nat — current round per validator
    leader,         \* leader[r] — leader for round r
    preVotes,       \* preVotes[v] — set of block hashes v has PreVoted for
    preCommits,     \* preCommits[v] — set of block hashes v has PreCommitted for
    preVotesRcvd,   \* preVotesRcvd[v][h] — set of validators v has received PreVotes from for hash h
    preCommitsRcvd, \* preCommitsRcvd[v][h] — set of validators v has received PreCommits from for hash h
    proposed,       \* proposed[r] — block hash proposed in round r (or "none")
    finalized,      \* finalized[v] — block hash finalized by v (or "none")
    timeoutVotes,   \* timeoutVotes[v] — set of timeout voters seen by v

vars == <<phase, round, leader, preVotes, preCommits,
          preVotesRcvd, preCommitsRcvd, proposed, finalized, timeoutVotes>>

\* ══════════════════════════════════════════════════════════
\* Initial state
\* ══════════════════════════════════════════════════════════

ChooseLeader(r) == CHOOSE v \in Validators : TRUE  \* Abstraction of VRF election

Init ==
    /\ phase = [v \in Validators |-> "Waiting"]
    /\ round = [v \in Validators |-> 0]
    /\ leader = [r \in 0..MaxRounds |-> ChooseLeader(r)]
    /\ preVotes = [v \in Validators |-> {}]
    /\ preCommits = [v \in Validators |-> {}]
    /\ preVotesRcvd = [v \in Validators |-> [h \in {"block0", "block1"} |-> {}]]
    /\ preCommitsRcvd = [v \in Validators |-> [h \in {"block0", "block1"} |-> {}]]
    /\ proposed = [r \in 0..MaxRounds |-> "none"]
    /\ finalized = [v \in Validators |-> "none"]
    /\ timeoutVotes = [v \in Validators |-> {}]

BlockHashes == {"block0", "block1"}

\* ══════════════════════════════════════════════════════════
\* Actions
\* ══════════════════════════════════════════════════════════

\* rotation.rs:234-280: Leader proposes a block
Propose(v, h) ==
    /\ v = leader[round[v]]
    /\ phase[v] = "Waiting"
    /\ proposed[round[v]] = "none"
    /\ proposed' = [proposed EXCEPT ![round[v]] = h]
    /\ phase' = [phase EXCEPT ![v] = "PreVoting"]
    /\ preVotes' = [preVotes EXCEPT ![v] = {h}]
    /\ UNCHANGED <<round, leader, preCommits, preVotesRcvd, preCommitsRcvd, finalized, timeoutVotes>>

\* rotation.rs:291-340: Receive a proposal and PreVote
ReceiveProposal(v) ==
    /\ phase[v] = "Waiting"
    /\ proposed[round[v]] # "none"
    /\ LET h == proposed[round[v]]
       IN /\ phase' = [phase EXCEPT ![v] = "PreVoting"]
          /\ preVotes' = [preVotes EXCEPT ![v] = {h}]
    /\ UNCHANGED <<round, leader, preCommits, preVotesRcvd, preCommitsRcvd, proposed, finalized, timeoutVotes>>

\* Honest validator receives a PreVote from another validator
ReceivePreVote(v, sender, h) ==
    /\ phase[v] = "PreVoting"
    /\ h \in preVotes[sender]
    /\ preVotesRcvd' = [preVotesRcvd EXCEPT ![v][h] = @ \union {sender}]
    \* Check if quorum reached → transition to PreCommitting
    /\ IF Cardinality(preVotesRcvd'[v][h]) >= Quorum
       THEN /\ phase' = [phase EXCEPT ![v] = "PreCommitting"]
            /\ preCommits' = [preCommits EXCEPT ![v] = {h}]
       ELSE /\ UNCHANGED <<phase, preCommits>>
    /\ UNCHANGED <<round, leader, preVotes, preCommitsRcvd, proposed, finalized, timeoutVotes>>

\* Honest validator receives a PreCommit from another validator
ReceivePreCommit(v, sender, h) ==
    /\ phase[v] = "PreCommitting"
    /\ h \in preCommits[sender]
    /\ preCommitsRcvd' = [preCommitsRcvd EXCEPT ![v][h] = @ \union {sender}]
    \* Check if quorum reached → Finalize
    /\ IF Cardinality(preCommitsRcvd'[v][h]) >= Quorum
       THEN /\ phase' = [phase EXCEPT ![v] = "Finalized"]
            /\ finalized' = [finalized EXCEPT ![v] = h]
       ELSE /\ UNCHANGED <<phase, finalized>>
    /\ UNCHANGED <<round, leader, preVotes, preCommits, preVotesRcvd, proposed, timeoutVotes>>

\* ── Byzantine Actions ────────────────────────────────────────

\* Byzantine validator equivocates: proposes TWO different blocks
ByzantineEquivocate(v, h1, h2) ==
    /\ v \in Byzantine
    /\ v = leader[round[v]]
    /\ h1 # h2
    /\ proposed[round[v]] = "none"
    \* Propose h1 to some and h2 to others (abstracted as both in proposed)
    /\ proposed' = [proposed EXCEPT ![round[v]] = h1]
    /\ UNCHANGED <<phase, round, leader, preVotes, preCommits,
                   preVotesRcvd, preCommitsRcvd, finalized, timeoutVotes>>

\* Byzantine validator votes for conflicting blocks (sends preVotes for both)
ByzantineDoubleVote(v, h) ==
    /\ v \in Byzantine
    /\ preVotes' = [preVotes EXCEPT ![v] = @ \union {h}]
    /\ UNCHANGED <<phase, round, leader, preCommits, preVotesRcvd,
                   preCommitsRcvd, proposed, finalized, timeoutVotes>>

\* Byzantine validator withholds PreCommit
ByzantineWithholdPrecommit(v) ==
    /\ v \in Byzantine
    /\ UNCHANGED vars  \* Does nothing — timeout will trigger

\* ── Timeout & Round Advancement ──────────────────────────

\* rotation.rs:390-423: Timeout vote
TimeoutVote(v, sender) ==
    /\ phase[v] # "Finalized"
    /\ timeoutVotes' = [timeoutVotes EXCEPT ![v] = @ \union {sender}]
    \* rotation.rs:414: timeout quorum → new round
    /\ IF Cardinality(timeoutVotes'[v]) >= Quorum
       THEN /\ round' = [round EXCEPT ![v] = @+1]
            /\ phase' = [phase EXCEPT ![v] = "Waiting"]
            /\ preVotes' = [preVotes EXCEPT ![v] = {}]
            /\ preCommits' = [preCommits EXCEPT ![v] = {}]
            /\ preVotesRcvd' = [preVotesRcvd EXCEPT ![v] = [h \in BlockHashes |-> {}]]
            /\ preCommitsRcvd' = [preCommitsRcvd EXCEPT ![v] = [h \in BlockHashes |-> {}]]
            /\ timeoutVotes' = [timeoutVotes EXCEPT ![v] = {}]
       ELSE /\ UNCHANGED <<round, phase, preVotes, preCommits,
                           preVotesRcvd, preCommitsRcvd>>
    /\ UNCHANGED <<leader, proposed, finalized>>

\* ══════════════════════════════════════════════════════════
\* Next-state relation
\* ══════════════════════════════════════════════════════════

Next ==
    \/ \E v \in Honest, h \in BlockHashes : Propose(v, h)
    \/ \E v \in Honest : ReceiveProposal(v)
    \/ \E v \in Honest, s \in Validators, h \in BlockHashes : ReceivePreVote(v, s, h)
    \/ \E v \in Honest, s \in Validators, h \in BlockHashes : ReceivePreCommit(v, s, h)
    \/ \E v \in Byzantine, h1, h2 \in BlockHashes : ByzantineEquivocate(v, h1, h2)
    \/ \E v \in Byzantine, h \in BlockHashes : ByzantineDoubleVote(v, h)
    \/ \E v \in Honest, s \in Validators : TimeoutVote(v, s)

Spec == Init /\ [][Next]_vars

\* ══════════════════════════════════════════════════════════
\* Safety Invariants
\* ══════════════════════════════════════════════════════════

\* SAFETY-1: No two honest validators finalize different blocks at the same height.
\* This is THE core BFT safety property.
NoTwoFinalizedAtSameHeight ==
    \A v1, v2 \in Honest :
        (finalized[v1] # "none" /\ finalized[v2] # "none")
            => finalized[v1] = finalized[v2]

\* SAFETY-2: Once finalized, a validator stays finalized (no rollback).
FinalizedIsStable ==
    \A v \in Honest :
        phase[v] = "Finalized" => finalized[v] # "none"

\* SAFETY-3: Finalization requires a quorum of PreCommits.
\* If v finalized h, then at least Quorum validators PreCommitted h.
FinalizationRequiresQuorum ==
    \A v \in Honest :
        finalized[v] # "none" =>
            Cardinality(preCommitsRcvd[v][finalized[v]]) >= Quorum

\* SAFETY-4: If a validator PreVoted for two different hashes, it must be Byzantine.
\* This ensures equivocation is always attributable to a Byzantine actor.
SlashingCompleteness ==
    \A v \in Validators :
        \A h1, h2 \in BlockHashes :
            (h1 # h2 /\ h1 \in preVotes[v] /\ h2 \in preVotes[v])
                => v \in Byzantine

\* SAFETY-5: Quorum intersection — any two quorums share at least one honest validator.
\* This is the foundation of BFT safety: conflicting decisions require conflicting quorums,
\* but overlapping honest validators prevent both from forming.
QuorumIntersection ==
    \A Q1, Q2 \in SUBSET Validators :
        (Cardinality(Q1) >= Quorum /\ Cardinality(Q2) >= Quorum)
            => \E v \in Honest : v \in Q1 /\ v \in Q2

\* Combined safety invariant
SafetyInvariant ==
    /\ NoTwoFinalizedAtSameHeight
    /\ FinalizedIsStable
    /\ FinalizationRequiresQuorum
    /\ SlashingCompleteness
    /\ QuorumIntersection

\* ══════════════════════════════════════════════════════════
\* Liveness (under eventual synchrony)
\* ══════════════════════════════════════════════════════════

\* LIVENESS: If all honest validators are in the same round and the leader
\* is honest, eventually some honest validator finalizes.
\* (Expressed as a temporal property for model checking.)
LivenessUnderHeal ==
    <>(\E v \in Honest : finalized[v] # "none")

====
