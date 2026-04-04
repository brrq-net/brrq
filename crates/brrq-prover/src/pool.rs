//! Cooperative prover pools — whitepaper §14.3.
//!
//! Allows provers with modest hardware to participate in STARK proof
//! generation by pooling resources. A coordinator manages the pool,
//! assigns proof tasks to members, and distributes rewards proportional
//! to each member's declared weight.
//!
//! ## Reward Distribution
//!
//! When a task completes:
//! 1. The coordinator takes a fee (≤10%, configurable in basis points).
//! 2. The remaining reward is split among all members proportional to weight.
//! 3. The coordinator also receives their weight-proportional share of the
//!    remaining reward, in addition to the fee.

use imbl::HashMap;

use brrq_crypto::hash::{Hash256, Hasher};
use brrq_types::Address;
use serde::{Deserialize, Serialize};

/// Maximum number of members in a single prover pool.
pub const MAX_POOL_SIZE: usize = 100;

/// Maximum coordinator fee in basis points (1000 bp = 10%).
pub const MAX_COORDINATOR_FEE_BP: u64 = 1000;

// ── Proof Economics Constants (Economic Specification §6) ───────────────

/// Proof deadline in L2 blocks after block production.
/// At 3s/block: 10s ≈ 3 blocks.
pub const PROOF_DEADLINE_BLOCKS: u64 = 3;

/// Backup prover grace period in L2 blocks after primary deadline.
/// At 3s/block: 30s ≈ 10 blocks.
pub const PROOF_FALLBACK_BLOCKS: u64 = 10;

/// Bond multiplier: prover must post bond = expected_reward × this factor.
/// If proof is delivered on time, bond is returned with reward.
/// If proof is late/invalid, bond is forfeited to backup prover.
pub const PROOF_BOND_MULTIPLIER: u64 = 2;

/// Backup prover reward multiplier in basis points (15000 = 150%).
/// Backup prover gets 150% of the normal reward (normal + forfeited primary bond portion).
pub const BACKUP_REWARD_MULTIPLIER_BP: u64 = 15000;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A cooperative prover pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverPool {
    /// Unique identifier for this pool.
    pub pool_id: Hash256,
    /// Address of the pool coordinator.
    pub coordinator: Address,
    /// Human-readable pool name.
    pub name: String,
    /// Current pool members keyed by address.
    pub members: HashMap<Address, PoolMember>,
    /// Total number of proofs this pool has generated.
    pub proofs_generated: u64,
    /// Cumulative reward earned by this pool.
    pub total_reward: u64,
    /// Coordinator fee in basis points (100 bp = 1%).
    pub coordinator_fee_bp: u64,
    /// Block height at which this pool was created.
    pub created_at: u64,
    /// Whether the pool is open for new members.
    pub open: bool,
}

/// A member within a prover pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolMember {
    /// Member address.
    pub address: Address,
    /// Declared contribution weight (determines reward share).
    pub weight: u64,
    /// Number of proofs this member has contributed.
    pub proofs_contributed: u64,
    /// Total reward earned by this member.
    pub reward_earned: u64,
    /// Block height at which this member joined.
    pub joined_at: u64,
}

/// A proof-generation task that can be assigned to a pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofTask {
    /// Unique task identifier.
    pub task_id: Hash256,
    /// Inclusive block range (start, end) to prove.
    pub block_range: (u64, u64),
    /// Pool this task is assigned to, if any.
    pub assigned_to: Option<Hash256>,
    /// Current task status.
    pub status: TaskStatus,
    /// Block height at which this task was created.
    pub created_at: u64,
    /// Reward offered for completing this task.
    pub reward: u64,
    /// Bond posted by the assigned pool (returned on success, forfeited on timeout).
    pub bond: Option<ProofBond>,
    /// L2 block height deadline for primary prover.
    pub primary_deadline: Option<u64>,
    /// L2 block height deadline for backup prover.
    pub backup_deadline: Option<u64>,
}

/// Bond posted by a prover pool when accepting a proof task.
///
/// Economic Specification §6.4:
/// - Prover posts bond = 2× expected reward
/// - On-time delivery: bond returned + reward paid
/// - Late/invalid: bond forfeited to backup prover
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofBond {
    /// Pool that posted the bond.
    pub pool_id: Hash256,
    /// Bond amount in satoshis.
    pub amount: u64,
    /// L2 block height when bond was posted.
    pub posted_at: u64,
    /// Whether the bond has been returned or forfeited.
    pub status: BondStatus,
}

/// Status of a proof bond.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BondStatus {
    /// Bond is active (proof in progress).
    Active,
    /// Bond returned to prover (proof delivered on time).
    Returned,
    /// Bond forfeited (proof late or invalid).
    Forfeited,
}

/// Status of a proof task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskStatus {
    /// Task is waiting for assignment.
    Pending,
    /// Task has been assigned to a pool.
    Assigned,
    /// Proof has been submitted, awaiting verification.
    Submitted,
    /// Task is fully completed and rewards distributed.
    Completed,
    /// Task failed and may be reassigned.
    Failed,
}

/// Aggregate statistics across all pools.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolStats {
    /// Number of registered pools.
    pub total_pools: usize,
    /// Total members across all pools.
    pub total_members: usize,
    /// Cumulative proofs generated across all pools.
    pub total_proofs: u64,
    /// Cumulative rewards distributed across all pools.
    pub total_rewards: u64,
    /// Number of tasks in Pending status.
    pub pending_tasks: usize,
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

/// Manages the lifecycle of prover pools and proof tasks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverPoolManager {
    /// All registered pools, keyed by pool_id.
    pools: HashMap<Hash256, ProverPool>,
    /// All proof tasks, keyed by task_id.
    tasks: HashMap<Hash256, ProofTask>,
    /// Reverse index: member address → pool_id they belong to.
    member_pools: HashMap<Address, Hash256>,
    /// Aggregate statistics.
    stats: PoolStats,
}

impl ProverPoolManager {
    /// Create a new, empty pool manager.
    pub fn new() -> Self {
        Self {
            pools: HashMap::new(),
            tasks: HashMap::new(),
            member_pools: HashMap::new(),
            stats: PoolStats {
                total_pools: 0,
                total_members: 0,
                total_proofs: 0,
                total_rewards: 0,
                pending_tasks: 0,
            },
        }
    }

    /// Create a new prover pool.
    ///
    /// The coordinator is automatically added as the first member with weight 100.
    /// Returns the generated pool ID.
    pub fn create_pool(
        &mut self,
        coordinator: Address,
        name: String,
        coordinator_fee_bp: u64,
        current_height: u64,
    ) -> Result<Hash256, String> {
        if coordinator_fee_bp > MAX_COORDINATOR_FEE_BP {
            return Err(format!(
                "coordinator fee {} bp exceeds maximum {} bp",
                coordinator_fee_bp, MAX_COORDINATOR_FEE_BP
            ));
        }

        if name.is_empty() {
            return Err("pool name cannot be empty".into());
        }

        if self.member_pools.contains_key(&coordinator) {
            return Err("coordinator is already a member of another pool".into());
        }

        // Derive a deterministic pool_id from coordinator + name + height.
        let pool_id = {
            let mut h = Hasher::new();
            h.update(coordinator.as_bytes());
            h.update(name.as_bytes());
            h.update(&current_height.to_le_bytes());
            h.finalize()
        };

        // Auto-add coordinator as the first member.
        let coordinator_member = PoolMember {
            address: coordinator,
            weight: 100,
            proofs_contributed: 0,
            reward_earned: 0,
            joined_at: current_height,
        };

        let mut members = HashMap::new();
        members.insert(coordinator, coordinator_member);

        let pool = ProverPool {
            pool_id,
            coordinator,
            name,
            members,
            proofs_generated: 0,
            total_reward: 0,
            coordinator_fee_bp,
            created_at: current_height,
            open: true,
        };

        // Guard against pool ID collision (deterministic hash could collide
        // if same coordinator + name + height is reused).
        if self.pools.contains_key(&pool_id) {
            return Err("pool ID collision; try a different name or height".into());
        }

        self.pools.insert(pool_id, pool);
        self.member_pools.insert(coordinator, pool_id);

        // Update stats.
        self.stats.total_pools += 1;
        self.stats.total_members += 1;

        Ok(pool_id)
    }

    /// Join an existing pool.
    ///
    /// The member must not already be in any pool. Weight must be > 0.
    pub fn join_pool(
        &mut self,
        pool_id: Hash256,
        member: Address,
        weight: u64,
        current_height: u64,
    ) -> Result<(), String> {
        // Check that the member is not already in a pool.
        if self.member_pools.contains_key(&member) {
            return Err("member is already in a pool".into());
        }

        if weight == 0 {
            return Err("weight must be greater than zero".into());
        }

        let pool = self
            .pools
            .get_mut(&pool_id)
            .ok_or_else(|| "pool not found".to_string())?;

        if !pool.open {
            return Err("pool is not open for new members".into());
        }

        if pool.members.len() >= MAX_POOL_SIZE {
            return Err(format!("pool is full (max {} members)", MAX_POOL_SIZE));
        }

        let pool_member = PoolMember {
            address: member,
            weight,
            proofs_contributed: 0,
            reward_earned: 0,
            joined_at: current_height,
        };

        pool.members.insert(member, pool_member);
        self.member_pools.insert(member, pool_id);
        self.stats.total_members += 1;

        Ok(())
    }

    /// Leave a pool.
    ///
    /// The coordinator cannot leave — they must close the pool instead.
    pub fn leave_pool(&mut self, pool_id: Hash256, member: Address) -> Result<(), String> {
        let pool = self
            .pools
            .get_mut(&pool_id)
            .ok_or_else(|| "pool not found".to_string())?;

        if pool.coordinator == member {
            return Err("coordinator cannot leave the pool; close it instead".into());
        }

        if pool.members.remove(&member).is_none() {
            return Err("member not found in this pool".into());
        }

        self.member_pools.remove(&member);
        self.stats.total_members = self.stats.total_members.saturating_sub(1);

        Ok(())
    }

    /// Close a pool. Only the coordinator can close it.
    /// The pool must have no active (Assigned/Submitted) tasks.
    pub fn close_pool(&mut self, pool_id: &Hash256, caller: &Address) -> Result<(), String> {
        let pool = self.pools.get(pool_id).ok_or("pool not found")?;
        if pool.coordinator != *caller {
            return Err("only the coordinator can close the pool".into());
        }
        // Check no active tasks
        let has_active = self.tasks.values().any(|t| {
            t.assigned_to.as_ref() == Some(pool_id)
                && matches!(t.status, TaskStatus::Assigned | TaskStatus::Submitted)
        });
        if has_active {
            return Err("cannot close pool with active tasks".into());
        }
        let pool = self
            .pools
            .get_mut(pool_id)
            .ok_or_else(|| "pool not found after validation".to_string())?;
        pool.open = false;
        // Remove members from member_pools index
        let member_addrs: Vec<Address> = pool.members.keys().cloned().collect();
        let member_count = member_addrs.len();
        for addr in &member_addrs {
            self.member_pools.remove(addr);
        }
        // Clear pool members to avoid stale forward references
        pool.members.clear();
        self.stats.total_members = self.stats.total_members.saturating_sub(member_count);
        self.stats.total_pools = self.stats.total_pools.saturating_sub(1);
        Ok(())
    }

    /// Create a new proof task.
    ///
    /// Returns the generated task ID.
    pub fn create_task(
        &mut self,
        block_range: (u64, u64),
        reward: u64,
        current_height: u64,
    ) -> Result<Hash256, String> {
        if block_range.0 > block_range.1 {
            return Err(format!(
                "invalid block range: start {} > end {}",
                block_range.0, block_range.1
            ));
        }

        let task_id = {
            let mut h = Hasher::new();
            h.update(&block_range.0.to_le_bytes());
            h.update(&block_range.1.to_le_bytes());
            h.update(&current_height.to_le_bytes());
            // Include monotonic counter to avoid ID collisions.
            h.update(&(self.tasks.len() as u64).to_le_bytes());
            h.finalize()
        };

        let task = ProofTask {
            task_id,
            block_range,
            assigned_to: None,
            status: TaskStatus::Pending,
            created_at: current_height,
            reward,
            bond: None,
            primary_deadline: None,
            backup_deadline: None,
        };

        self.tasks.insert(task_id, task);
        self.stats.pending_tasks += 1;

        Ok(task_id)
    }

    /// Create a task AND assign it via weighted lottery.
    ///
    /// Instead of first-come-first-serve (which lets whale farms monopolize all tasks),
    /// this uses a deterministic VRF-style lottery:
    /// 1. All open pools participate
    /// 2. Each pool's chance = its total_reward (proxy for stake/reputation)
    /// 3. Winner gets exclusive window (PROOF_DEADLINE_BLOCKS) to submit proof
    /// 4. If winner fails → bond slashed → backup lottery
    ///
    /// The lottery seed = H(block_hash || task_id) — deterministic and verifiable.
    pub fn create_and_assign_task(
        &mut self,
        block_range: (u64, u64),
        reward: u64,
        current_height: u64,
        block_hash: Hash256,
    ) -> Result<(Hash256, Option<Hash256>), String> {
        let task_id = self.create_task(block_range, reward, current_height)?;

        // Collect eligible pools with weights
        let eligible: Vec<(Hash256, u64)> = self.pools.iter()
            .filter(|(_, p)| p.open && !p.members.is_empty())
            .map(|(id, p)| {
                // Weight = total_reward + 1 (ensure non-zero for new pools)
                (*id, p.total_reward.saturating_add(1))
            })
            .collect();

        if eligible.is_empty() {
            return Ok((task_id, None)); // No pools available — task stays Pending
        }

        let winner_id = weighted_lottery(&eligible, block_hash, task_id);

        // Assign to winner
        if let Err(_e) = self.assign_task(task_id, winner_id) {
            // Winner pool became invalid between check and assign — task stays Pending
            return Ok((task_id, None));
        }

        Ok((task_id, Some(winner_id)))
    }

    /// Assign a pending or failed task to a pool.
    ///
    /// Tasks in `Failed` state (e.g., after a bond forfeit in `check_proof_deadlines`)
    /// can be reassigned to a backup prover.
    /// Restricted to crate-internal. External callers MUST use assign_task_with_bond.
    pub(crate) fn assign_task(&mut self, task_id: Hash256, pool_id: Hash256) -> Result<(), String> {
        let pool = self.pools.get(&pool_id).ok_or("pool not found")?;
        if !pool.open {
            return Err("cannot assign task to a closed pool".into());
        }

        let task = self
            .tasks
            .get_mut(&task_id)
            .ok_or_else(|| "task not found".to_string())?;

        if !matches!(task.status, TaskStatus::Pending | TaskStatus::Failed) {
            return Err(format!(
                "task must be pending or failed to assign (current status: {:?})",
                task.status
            ));
        }

        let was_pending = task.status == TaskStatus::Pending;
        task.status = TaskStatus::Assigned;
        task.assigned_to = Some(pool_id);
        if was_pending {
            self.stats.pending_tasks = self.stats.pending_tasks.saturating_sub(1);
        }

        Ok(())
    }

    /// Submit a proof for an assigned task.
    ///
    /// The submitter must be a member of the assigned pool.
    pub fn submit_proof(&mut self, task_id: Hash256, submitter: Address) -> Result<(), String> {
        let task = self
            .tasks
            .get(&task_id)
            .ok_or_else(|| "task not found".to_string())?;

        if task.status != TaskStatus::Assigned {
            return Err(format!(
                "task is not assigned (current status: {:?})",
                task.status
            ));
        }

        let pool_id = task
            .assigned_to
            .ok_or_else(|| "task has no assigned pool".to_string())?;

        let pool = self
            .pools
            .get(&pool_id)
            .ok_or_else(|| "assigned pool not found".to_string())?;

        if !pool.members.contains_key(&submitter) {
            return Err("submitter is not a member of the assigned pool".into());
        }

        // Increment submitter's contribution count.
        let pool = self
            .pools
            .get_mut(&pool_id)
            .ok_or_else(|| "pool not found after validation".to_string())?;
        pool.members
            .get_mut(&submitter)
            .ok_or_else(|| "pool member not found after validation".to_string())?
            .proofs_contributed += 1;

        // Update task status.
        let task = self
            .tasks
            .get_mut(&task_id)
            .ok_or_else(|| "task not found after validation".to_string())?;
        task.status = TaskStatus::Submitted;

        Ok(())
    }

    /// Complete a submitted task and distribute rewards.
    ///
    /// Returns a map of address → reward amount for each member.
    ///
    /// ## Reward Distribution
    ///
    /// 1. `coordinator_fee = reward * coordinator_fee_bp / 10000`
    /// 2. `remaining = reward - coordinator_fee`
    /// 3. Each member receives `remaining * (member_weight / total_weight)`
    /// 4. The coordinator receives the fee **plus** their weight-proportional
    ///    share of the remaining reward.
    pub fn complete_task(&mut self, task_id: Hash256) -> Result<HashMap<Address, u64>, String> {
        let task = self
            .tasks
            .get(&task_id)
            .ok_or_else(|| "task not found".to_string())?;

        if task.status != TaskStatus::Submitted {
            return Err(format!(
                "task is not submitted (current status: {:?})",
                task.status
            ));
        }

        let pool_id = task
            .assigned_to
            .ok_or_else(|| "task has no assigned pool".to_string())?;
        let reward = task.reward;

        let pool = self
            .pools
            .get(&pool_id)
            .ok_or_else(|| "assigned pool not found".to_string())?;

        let rewards = calculate_reward_distribution(pool, reward)?;

        // Apply rewards to pool members.
        let pool = self
            .pools
            .get_mut(&pool_id)
            .ok_or_else(|| "pool not found after validation".to_string())?;
        for (addr, amount) in &rewards {
            if let Some(member) = pool.members.get_mut(addr) {
                member.reward_earned += amount;
            }
        }
        pool.proofs_generated += 1;
        pool.total_reward += reward;

        // Update task status.
        let task = self
            .tasks
            .get_mut(&task_id)
            .ok_or_else(|| "task not found after validation".to_string())?;
        task.status = TaskStatus::Completed;

        // Update global stats.
        self.stats.total_proofs += 1;
        self.stats.total_rewards += reward;

        Ok(rewards)
    }

    /// Fail an assigned or submitted task, making it eligible for reassignment.
    ///
    /// Only tasks in `Assigned` or `Submitted` status can be failed.
    /// If the task has an active bond, it is forfeited.
    pub fn fail_task(&mut self, task_id: Hash256) -> Result<(), String> {
        let task = self
            .tasks
            .get_mut(&task_id)
            .ok_or_else(|| "task not found".to_string())?;
        if !matches!(task.status, TaskStatus::Assigned | TaskStatus::Submitted) {
            return Err(format!("cannot fail task in status {:?}", task.status));
        }
        task.status = TaskStatus::Failed;
        task.assigned_to = None;
        // Forfeit any active bond — prover failed to deliver.
        if let Some(bond) = &mut task.bond
            && bond.status == BondStatus::Active
        {
            bond.status = BondStatus::Forfeited;
        }
        Ok(())
    }

    // ── Proof Economics: Bond + Deadline Methods ─────────────────────

    /// Assign a task with a proof bond (Economic Specification §6.4).
    ///
    /// The pool must post `bond_amount = task.reward × PROOF_BOND_MULTIPLIER`.
    /// Deadlines are set: primary at `current_height + PROOF_DEADLINE_BLOCKS`,
    /// backup at `current_height + PROOF_DEADLINE_BLOCKS + PROOF_FALLBACK_BLOCKS`.
    ///
    /// Accepts tasks in `Pending` or `Failed` state (backup prover assignment
    /// after bond forfeit via `check_proof_deadlines`).
    pub fn assign_task_with_bond(
        &mut self,
        task_id: Hash256,
        pool_id: Hash256,
        current_height: u64,
    ) -> Result<u64, String> {
        let pool = self.pools.get(&pool_id).ok_or("pool not found")?;
        if !pool.open {
            return Err("cannot assign task to a closed pool".into());
        }

        let task = self
            .tasks
            .get(&task_id)
            .ok_or_else(|| "task not found".to_string())?;

        if !matches!(task.status, TaskStatus::Pending | TaskStatus::Failed) {
            return Err(format!(
                "task must be pending or failed to assign (current status: {:?})",
                task.status
            ));
        }

        // Calculate required bond: reward × multiplier.
        // Use u128 to prevent overflow.
        let bond_amount =
            (task.reward as u128 * PROOF_BOND_MULTIPLIER as u128).min(u64::MAX as u128) as u64;

        let primary_deadline = current_height.saturating_add(PROOF_DEADLINE_BLOCKS);
        let backup_deadline = primary_deadline.saturating_add(PROOF_FALLBACK_BLOCKS);

        let bond = ProofBond {
            pool_id,
            amount: bond_amount,
            posted_at: current_height,
            status: BondStatus::Active,
        };

        let task = self
            .tasks
            .get_mut(&task_id)
            .ok_or_else(|| "task not found".to_string())?;

        let was_pending = task.status == TaskStatus::Pending;
        task.status = TaskStatus::Assigned;
        task.assigned_to = Some(pool_id);
        task.bond = Some(bond);
        task.primary_deadline = Some(primary_deadline);
        task.backup_deadline = Some(backup_deadline);
        if was_pending {
            self.stats.pending_tasks = self.stats.pending_tasks.saturating_sub(1);
        }

        Ok(bond_amount)
    }

    /// Check proof deadlines and forfeit bonds for expired tasks.
    ///
    /// Returns a list of (task_id, forfeited_bond_amount) pairs for tasks
    /// that missed their primary deadline and need backup provers.
    ///
    /// Economic Specification §6.4:
    /// - After primary deadline: bond forfeited, task reopened for backup
    /// - After backup deadline: emergency reproof by full pool
    pub fn check_proof_deadlines(&mut self, current_height: u64) -> Vec<(Hash256, u64)> {
        let mut forfeited: Vec<(Hash256, u64)> = Vec::new();

        // Collect tasks that missed primary deadline.
        let overdue_tasks: Vec<Hash256> = self
            .tasks
            .iter()
            .filter(|(_, t)| {
                t.status == TaskStatus::Assigned
                    && t.primary_deadline.is_some_and(|d| current_height > d)
                    && t.bond
                        .as_ref()
                        .is_some_and(|b| b.status == BondStatus::Active)
            })
            .map(|(id, _)| *id)
            .collect();

        for task_id in overdue_tasks {
            if let Some(task) = self.tasks.get_mut(&task_id) {
                let bond_amount = task.bond.as_ref().map_or(0, |b| b.amount);

                // Forfeit the bond.
                if let Some(bond) = &mut task.bond {
                    bond.status = BondStatus::Forfeited;
                }

                // Re-open task as Failed (can be reassigned to backup).
                task.status = TaskStatus::Failed;
                task.assigned_to = None;

                // Increase reward for backup prover (150% of original).
                let backup_reward =
                    (task.reward as u128 * BACKUP_REWARD_MULTIPLIER_BP as u128 / 10_000) as u64;
                task.reward = backup_reward;

                forfeited.push((task_id, bond_amount));
            }
        }

        forfeited
    }

    /// Complete a task and return the bond to the prover.
    ///
    /// On successful proof delivery, the bond is marked as Returned
    /// and the normal reward distribution applies.
    pub fn complete_task_with_bond(
        &mut self,
        task_id: Hash256,
    ) -> Result<(HashMap<Address, u64>, u64), String> {
        // Return the bond first.
        let bond_amount = {
            let task = self
                .tasks
                .get_mut(&task_id)
                .ok_or_else(|| "task not found".to_string())?;

            if let Some(bond) = &mut task.bond {
                if bond.status == BondStatus::Active {
                    bond.status = BondStatus::Returned;
                }
                bond.amount
            } else {
                0
            }
        };

        // Then distribute rewards normally.
        let rewards = self.complete_task(task_id)?;
        Ok((rewards, bond_amount))
    }

    /// Look up a pool by ID.
    pub fn get_pool(&self, pool_id: Hash256) -> Option<&ProverPool> {
        self.pools.get(&pool_id)
    }

    /// Return references to all pools.
    pub fn all_pools(&self) -> Vec<&ProverPool> {
        self.pools.values().collect()
    }

    /// Return all tasks matching the given status.
    pub fn tasks_by_status(&self, status: TaskStatus) -> Vec<&ProofTask> {
        self.tasks.values().filter(|t| t.status == status).collect()
    }

    /// Look up which pool a member belongs to.
    pub fn member_pool(&self, member: &Address) -> Option<&Hash256> {
        self.member_pools.get(member)
    }

    /// Return aggregate statistics.
    pub fn stats(&self) -> &PoolStats {
        &self.stats
    }
}

impl Default for ProverPoolManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Calculate reward distribution for a completed proof task.
///
/// 1. Coordinator fee = `reward * coordinator_fee_bp / 10000`
/// 2. Remaining reward split proportional to member weights
/// 3. Coordinator receives fee + their weight-proportional share
/// 4. Integer rounding dust goes to coordinator
fn calculate_reward_distribution(
    pool: &ProverPool,
    reward: u64,
) -> Result<HashMap<Address, u64>, String> {
    let total_weight: u64 = pool.members.values().map(|m| m.weight).sum();
    if total_weight == 0 {
        return Err("total weight is zero; cannot distribute rewards".into());
    }

    // 1. Coordinator fee.
    let coordinator_fee = (reward as u128 * pool.coordinator_fee_bp as u128 / 10_000) as u64;
    // 2. Remaining reward for weight-proportional distribution.
    let remaining = reward - coordinator_fee;

    // 3. Calculate each member's share.
    let mut rewards: HashMap<Address, u64> = HashMap::new();
    let mut member_shares_total: u64 = 0;
    for (addr, member) in &pool.members {
        let share = (remaining as u128 * member.weight as u128 / total_weight as u128) as u64;
        member_shares_total += share;
        let total_member_reward = if *addr == pool.coordinator {
            share + coordinator_fee
        } else {
            share
        };
        rewards.insert(*addr, total_member_reward);
    }

    // 4. Give rounding dust to the coordinator.
    let dust = remaining - member_shares_total;
    if dust > 0 {
        *rewards.entry(pool.coordinator).or_insert(0) += dust;
    }

    Ok(rewards)
}

/// Run a deterministic weighted lottery and return the winning pool ID.
///
/// Uses VRF-style deterministic seed to select
/// winner proportional to each pool's reputation weight.
fn weighted_lottery(
    eligible: &[(Hash256, u64)],
    block_hash: Hash256,
    task_id: Hash256,
) -> Hash256 {
    let total_weight: u64 = eligible.iter().map(|(_, w)| *w).sum();

    let lottery_seed = {
        let mut h = Hasher::new();
        h.update(b"BRRQ_PROVER_LOTTERY_V1");
        h.update(block_hash.as_bytes());
        h.update(task_id.as_bytes());
        h.finalize()
    };
    // Convert first 8 bytes of seed to u64, mod total_weight
    let seed_val = u64::from_le_bytes(
        lottery_seed.as_bytes()[..8].try_into().unwrap()
    );
    let target = seed_val % total_weight;

    // Walk cumulative weights to find winner
    let mut cumulative = 0u64;
    for (pool_id, weight) in eligible {
        cumulative = cumulative.saturating_add(*weight);
        if target < cumulative {
            return *pool_id;
        }
    }
    // Fallback (should never reach here if total_weight > 0)
    eligible[0].0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create an address from a single repeated byte.
    fn addr(byte: u8) -> Address {
        Address::from_bytes([byte; 20])
    }

    #[test]
    fn create_pool_valid() {
        let mut mgr = ProverPoolManager::new();
        let coordinator = addr(1);

        let result = mgr.create_pool(coordinator, "TestPool".into(), 500, 100);
        assert!(result.is_ok());

        let pool_id = result.unwrap();
        let pool = mgr.get_pool(pool_id).unwrap();
        assert_eq!(pool.coordinator, coordinator);
        assert_eq!(pool.name, "TestPool");
        assert_eq!(pool.coordinator_fee_bp, 500);
        assert_eq!(pool.created_at, 100);
        assert!(pool.open);
        assert_eq!(pool.members.len(), 1);
        assert!(pool.members.contains_key(&coordinator));
        assert_eq!(pool.members[&coordinator].weight, 100);
    }

    #[test]
    fn create_pool_excess_fee_rejected() {
        let mut mgr = ProverPoolManager::new();
        let result = mgr.create_pool(addr(1), "Pool".into(), MAX_COORDINATOR_FEE_BP + 1, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds maximum"));
    }

    #[test]
    fn create_pool_empty_name_rejected() {
        let mut mgr = ProverPoolManager::new();
        let result = mgr.create_pool(addr(1), "".into(), 500, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty"));
    }

    #[test]
    fn join_pool_valid() {
        let mut mgr = ProverPoolManager::new();
        let pool_id = mgr.create_pool(addr(1), "Pool".into(), 500, 0).unwrap();

        let result = mgr.join_pool(pool_id, addr(2), 50, 10);
        assert!(result.is_ok());

        let pool = mgr.get_pool(pool_id).unwrap();
        assert_eq!(pool.members.len(), 2);
        assert_eq!(pool.members[&addr(2)].weight, 50);
        assert_eq!(pool.members[&addr(2)].joined_at, 10);
    }

    #[test]
    fn join_pool_full_rejected() {
        let mut mgr = ProverPoolManager::new();
        let pool_id = mgr.create_pool(addr(0), "BigPool".into(), 100, 0).unwrap();

        // Pool already has the coordinator (1 member). Add MAX_POOL_SIZE - 1 more.
        for i in 1..MAX_POOL_SIZE {
            let member = Address::from_bytes({
                let mut bytes = [0u8; 20];
                let idx_bytes = (i as u32).to_le_bytes();
                bytes[..4].copy_from_slice(&idx_bytes);
                bytes
            });
            mgr.join_pool(pool_id, member, 10, 0).unwrap();
        }

        let pool = mgr.get_pool(pool_id).unwrap();
        assert_eq!(pool.members.len(), MAX_POOL_SIZE);

        // The next join should fail.
        let overflow_member = Address::from_bytes([0xFF; 20]);
        let result = mgr.join_pool(pool_id, overflow_member, 10, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("full"));
    }

    #[test]
    fn join_pool_already_member_rejected() {
        let mut mgr = ProverPoolManager::new();
        let pool_id = mgr.create_pool(addr(1), "Pool".into(), 500, 0).unwrap();
        mgr.join_pool(pool_id, addr(2), 50, 0).unwrap();

        // Try to join again.
        let result = mgr.join_pool(pool_id, addr(2), 50, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already"));
    }

    #[test]
    fn leave_pool_valid() {
        let mut mgr = ProverPoolManager::new();
        let pool_id = mgr.create_pool(addr(1), "Pool".into(), 500, 0).unwrap();
        mgr.join_pool(pool_id, addr(2), 50, 0).unwrap();

        let result = mgr.leave_pool(pool_id, addr(2));
        assert!(result.is_ok());

        let pool = mgr.get_pool(pool_id).unwrap();
        assert_eq!(pool.members.len(), 1);
        assert!(!pool.members.contains_key(&addr(2)));
        assert!(mgr.member_pool(&addr(2)).is_none());
    }

    #[test]
    fn leave_pool_coordinator_rejected() {
        let mut mgr = ProverPoolManager::new();
        let pool_id = mgr.create_pool(addr(1), "Pool".into(), 500, 0).unwrap();

        let result = mgr.leave_pool(pool_id, addr(1));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("coordinator"));
    }

    #[test]
    fn create_and_assign_task() {
        let mut mgr = ProverPoolManager::new();
        let pool_id = mgr.create_pool(addr(1), "Pool".into(), 500, 0).unwrap();

        let task_id = mgr.create_task((10, 20), 1000, 50).unwrap();

        let pending = mgr.tasks_by_status(TaskStatus::Pending);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].task_id, task_id);

        let result = mgr.assign_task(task_id, pool_id);
        assert!(result.is_ok());

        let assigned = mgr.tasks_by_status(TaskStatus::Assigned);
        assert_eq!(assigned.len(), 1);
        assert_eq!(assigned[0].assigned_to, Some(pool_id));
    }

    #[test]
    fn complete_task_distributes_rewards() {
        let mut mgr = ProverPoolManager::new();
        let pool_id = mgr.create_pool(addr(1), "Pool".into(), 500, 0).unwrap();
        mgr.join_pool(pool_id, addr(2), 100, 0).unwrap();

        let task_id = mgr.create_task((1, 10), 10_000, 0).unwrap();
        mgr.assign_task(task_id, pool_id).unwrap();
        mgr.submit_proof(task_id, addr(1)).unwrap();

        let rewards = mgr.complete_task(task_id).unwrap();

        // All reward should be accounted for (modulo integer rounding).
        let total_distributed: u64 = rewards.values().sum();
        assert!(total_distributed <= 10_000);
        assert!(total_distributed > 0);

        // Both members should receive something.
        assert!(rewards.contains_key(&addr(1)));
        assert!(rewards.contains_key(&addr(2)));

        // Pool stats should be updated.
        let pool = mgr.get_pool(pool_id).unwrap();
        assert_eq!(pool.proofs_generated, 1);
        assert_eq!(pool.total_reward, 10_000);
    }

    #[test]
    fn reward_distribution_proportional_to_weight() {
        let mut mgr = ProverPoolManager::new();
        // No coordinator fee to test pure weight-based distribution.
        let pool_id = mgr.create_pool(addr(1), "Pool".into(), 0, 0).unwrap();
        // Coordinator has weight 100 (auto-added).
        mgr.join_pool(pool_id, addr(2), 100, 0).unwrap();
        mgr.join_pool(pool_id, addr(3), 200, 0).unwrap();
        // Total weight = 100 + 100 + 200 = 400.

        let task_id = mgr.create_task((1, 10), 40_000, 0).unwrap();
        mgr.assign_task(task_id, pool_id).unwrap();
        mgr.submit_proof(task_id, addr(1)).unwrap();

        let rewards = mgr.complete_task(task_id).unwrap();

        // With 0% fee: each member gets reward * weight / total_weight.
        // addr(1): 40000 * 100 / 400 = 10000
        // addr(2): 40000 * 100 / 400 = 10000
        // addr(3): 40000 * 200 / 400 = 20000
        assert_eq!(rewards[&addr(1)], 10_000);
        assert_eq!(rewards[&addr(2)], 10_000);
        assert_eq!(rewards[&addr(3)], 20_000);
    }

    #[test]
    fn coordinator_fee_deducted() {
        let mut mgr = ProverPoolManager::new();
        // 10% coordinator fee (1000 bp).
        let pool_id = mgr.create_pool(addr(1), "Pool".into(), 1000, 0).unwrap();
        mgr.join_pool(pool_id, addr(2), 100, 0).unwrap();
        // Coordinator weight = 100, member weight = 100. Total = 200.

        let task_id = mgr.create_task((1, 10), 10_000, 0).unwrap();
        mgr.assign_task(task_id, pool_id).unwrap();
        mgr.submit_proof(task_id, addr(2)).unwrap();

        let rewards = mgr.complete_task(task_id).unwrap();

        // coordinator_fee = 10000 * 1000 / 10000 = 1000
        // remaining = 9000
        // addr(1) weight share = 9000 * 100 / 200 = 4500, plus fee: 4500 + 1000 = 5500
        // addr(2) weight share = 9000 * 100 / 200 = 4500
        assert_eq!(rewards[&addr(1)], 5_500);
        assert_eq!(rewards[&addr(2)], 4_500);
    }

    #[test]
    fn tasks_by_status_filter() {
        let mut mgr = ProverPoolManager::new();
        let pool_id = mgr.create_pool(addr(1), "Pool".into(), 0, 0).unwrap();

        let t1 = mgr.create_task((1, 5), 100, 0).unwrap();
        let t2 = mgr.create_task((6, 10), 200, 0).unwrap();
        let _t3 = mgr.create_task((11, 15), 300, 0).unwrap();

        assert_eq!(mgr.tasks_by_status(TaskStatus::Pending).len(), 3);
        assert_eq!(mgr.tasks_by_status(TaskStatus::Assigned).len(), 0);

        mgr.assign_task(t1, pool_id).unwrap();
        assert_eq!(mgr.tasks_by_status(TaskStatus::Pending).len(), 2);
        assert_eq!(mgr.tasks_by_status(TaskStatus::Assigned).len(), 1);

        mgr.assign_task(t2, pool_id).unwrap();
        mgr.submit_proof(t2, addr(1)).unwrap();
        assert_eq!(mgr.tasks_by_status(TaskStatus::Submitted).len(), 1);
    }

    #[test]
    fn pool_stats_tracking() {
        let mut mgr = ProverPoolManager::new();
        assert_eq!(mgr.stats().total_pools, 0);
        assert_eq!(mgr.stats().total_members, 0);

        let pool_id = mgr.create_pool(addr(1), "Alpha".into(), 500, 0).unwrap();
        assert_eq!(mgr.stats().total_pools, 1);
        assert_eq!(mgr.stats().total_members, 1);

        mgr.join_pool(pool_id, addr(2), 50, 0).unwrap();
        assert_eq!(mgr.stats().total_members, 2);

        let task_id = mgr.create_task((1, 10), 5_000, 0).unwrap();
        assert_eq!(mgr.stats().pending_tasks, 1);

        mgr.assign_task(task_id, pool_id).unwrap();
        assert_eq!(mgr.stats().pending_tasks, 0);

        mgr.submit_proof(task_id, addr(1)).unwrap();
        mgr.complete_task(task_id).unwrap();
        assert_eq!(mgr.stats().total_proofs, 1);
        assert_eq!(mgr.stats().total_rewards, 5_000);
    }

    #[test]
    fn close_pool_valid() {
        let mut mgr = ProverPoolManager::new();
        let pool_id = mgr.create_pool(addr(1), "Test".into(), 500, 0).unwrap();
        // Join a member
        mgr.join_pool(pool_id, addr(2), 100, 0).unwrap();
        // Close pool
        mgr.close_pool(&pool_id, &addr(1)).unwrap();
        // Pool should be closed
        assert!(!mgr.get_pool(pool_id).unwrap().open);
        // Member should be removed from member_pools
        assert!(mgr.member_pool(&addr(2)).is_none());
    }

    // --- test_pool_id_collision_rejected ---

    #[test]
    fn test_pool_id_collision_rejected() {
        let mut mgr = ProverPoolManager::new();
        let coordinator = addr(1);

        // Create a pool with specific coordinator, name, and height.
        let pool_id = mgr
            .create_pool(coordinator, "DupePool".into(), 500, 42)
            .unwrap();

        // Close the pool so the coordinator is removed from member_pools,
        // but the pool entry (and its pool_id) remains in the pools map.
        mgr.close_pool(&pool_id, &coordinator).unwrap();

        // Attempt to create another pool with the EXACT same inputs.
        // Since pool_id is derived from coordinator+name+height, this
        // should hit the collision guard.
        let result = mgr.create_pool(coordinator, "DupePool".into(), 500, 42);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("collision"),
            "expected collision error, got: {}",
            err
        );
    }

    // --- test_close_pool_decrements_stats ---

    #[test]
    fn test_close_pool_decrements_stats() {
        let mut mgr = ProverPoolManager::new();
        let coordinator = addr(1);

        let pool_id = mgr
            .create_pool(coordinator, "StatsPool".into(), 500, 0)
            .unwrap();
        mgr.join_pool(pool_id, addr(2), 50, 0).unwrap();
        mgr.join_pool(pool_id, addr(3), 75, 0).unwrap();

        // Before close: 1 pool, 3 members (coordinator + 2).
        assert_eq!(mgr.stats().total_pools, 1);
        assert_eq!(mgr.stats().total_members, 3);

        // Close the pool.
        mgr.close_pool(&pool_id, &coordinator).unwrap();

        // After close: 0 pools, 0 members.
        assert_eq!(mgr.stats().total_pools, 0);
        assert_eq!(mgr.stats().total_members, 0);
    }

    // --- test_close_pool_clears_members ---

    #[test]
    fn test_close_pool_clears_members() {
        let mut mgr = ProverPoolManager::new();
        let coordinator = addr(1);
        let member = addr(2);

        let pool_id = mgr
            .create_pool(coordinator, "ClearPool".into(), 500, 0)
            .unwrap();
        mgr.join_pool(pool_id, member, 50, 0).unwrap();

        // Close pool.
        mgr.close_pool(&pool_id, &coordinator).unwrap();

        // Pool members should be empty.
        let pool = mgr.get_pool(pool_id).unwrap();
        assert!(
            pool.members.is_empty(),
            "pool.members should be empty after close"
        );

        // member_pool() should return None for both the member and coordinator.
        assert!(
            mgr.member_pool(&member).is_none(),
            "member should not be in member_pools"
        );
        assert!(
            mgr.member_pool(&coordinator).is_none(),
            "coordinator should not be in member_pools"
        );
    }

    // --- test_create_task_invalid_range_rejected ---

    #[test]
    fn test_create_task_invalid_range_rejected() {
        let mut mgr = ProverPoolManager::new();

        // start (20) > end (10) -> invalid range.
        let result = mgr.create_task((20, 10), 1000, 0);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("invalid block range"),
            "expected invalid block range error, got: {}",
            err
        );
    }

    // --- test_fail_task_transitions_status ---

    #[test]
    fn test_fail_task_transitions_status() {
        let mut mgr = ProverPoolManager::new();
        let pool_id = mgr.create_pool(addr(1), "FailPool".into(), 0, 0).unwrap();

        let task_id = mgr.create_task((1, 10), 5000, 0).unwrap();
        mgr.assign_task(task_id, pool_id).unwrap();

        // Fail the task.
        mgr.fail_task(task_id).unwrap();

        // Verify status is Failed.
        let failed_tasks = mgr.tasks_by_status(TaskStatus::Failed);
        assert_eq!(failed_tasks.len(), 1);
        assert_eq!(failed_tasks[0].status, TaskStatus::Failed);

        // Verify assigned_to is None (cleared on failure).
        assert!(
            failed_tasks[0].assigned_to.is_none(),
            "assigned_to should be None after fail"
        );
    }

    // ── Tests: backup prover reassignment ──────────────────

    #[test]
    fn test_failed_task_can_be_reassigned() {
        let mut mgr = ProverPoolManager::new();
        let pool_a = mgr.create_pool(addr(1), "PoolA".into(), 0, 0).unwrap();
        let pool_b = mgr.create_pool(addr(2), "PoolB".into(), 0, 0).unwrap();

        let task_id = mgr.create_task((1, 10), 5000, 0).unwrap();
        mgr.assign_task(task_id, pool_a).unwrap();

        // Primary prover fails.
        mgr.fail_task(task_id).unwrap();

        // Backup prover can now pick up the Failed task.
        let result = mgr.assign_task(task_id, pool_b);
        assert!(
            result.is_ok(),
            "Failed task must be reassignable to backup prover: {:?}",
            result.err()
        );

        let assigned = mgr.tasks_by_status(TaskStatus::Assigned);
        assert_eq!(assigned.len(), 1);
        assert_eq!(assigned[0].assigned_to, Some(pool_b));
    }

    #[test]
    fn test_bond_forfeit_and_backup_reassignment() {
        let mut mgr = ProverPoolManager::new();
        let pool_a = mgr
            .create_pool(addr(1), "PrimaryPool".into(), 0, 0)
            .unwrap();
        let pool_b = mgr.create_pool(addr(2), "BackupPool".into(), 0, 0).unwrap();

        let task_id = mgr.create_task((1, 10), 10_000, 100).unwrap();
        let bond_amount = mgr.assign_task_with_bond(task_id, pool_a, 100).unwrap();
        assert_eq!(bond_amount, 20_000); // 2× reward

        // Advance past primary deadline (100 + 3 = 103).
        let forfeited = mgr.check_proof_deadlines(104);
        assert_eq!(forfeited.len(), 1);
        assert_eq!(forfeited[0].1, 20_000); // forfeited bond amount

        // Task should now be Failed with 150% reward.
        let failed = mgr.tasks_by_status(TaskStatus::Failed);
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].reward, 15_000); // 150% of original 10_000

        // Backup prover can now claim the task with a new bond.
        let backup_bond = mgr.assign_task_with_bond(task_id, pool_b, 105).unwrap();
        assert_eq!(backup_bond, 30_000); // 2× the new 15_000 reward

        let assigned = mgr.tasks_by_status(TaskStatus::Assigned);
        assert_eq!(assigned.len(), 1);
        assert_eq!(assigned[0].assigned_to, Some(pool_b));
    }

    #[test]
    fn test_fail_task_forfeits_active_bond() {
        let mut mgr = ProverPoolManager::new();
        let pool_id = mgr.create_pool(addr(1), "BondPool".into(), 0, 0).unwrap();

        let task_id = mgr.create_task((1, 5), 8000, 50).unwrap();
        mgr.assign_task_with_bond(task_id, pool_id, 50).unwrap();

        // Manually fail the task.
        mgr.fail_task(task_id).unwrap();

        // Verify bond was forfeited.
        let failed = mgr.tasks_by_status(TaskStatus::Failed);
        assert_eq!(failed.len(), 1);
        let bond = failed[0].bond.as_ref().unwrap();
        assert_eq!(
            bond.status,
            BondStatus::Forfeited,
            "bond should be forfeited when task is manually failed"
        );
    }
}
