#![no_std]
#![no_main]

use brrq_contract_sdk::*;

// ── Storage Slot Prefixes ───────────────────────────────────────────────────
const SLOT_OWNER: u32 = 0x00;
const SLOT_PENDING_OWNER: u32 = 0x10;
const SLOT_PENDING_TO: u32 = 0x20;
const SLOT_PENDING_AMOUNT: u32 = 0x21;
const SLOT_PENDING_UNLOCK: u32 = 0x22;

// ── Constants ─────────────────────────────────────────────────────────────────
/// 48 hours in seconds (48 * 3600)
const TIMELOCK_SECONDS: u64 = 172_800;
/// Max instant withdrawal: 1 BTC = 100_000_000 satoshis
const MAX_INSTANT_WITHDRAW: u64 = 100_000_000;

// ── Function Selectors ──────────────────────────────────────────────────────
const FN_DEPOSIT: u32         = 0x01;
const FN_WITHDRAW: u32        = 0x02;
// 0x03 was FN_SET_OWNER — replaced by two-step transfer
const FN_GET_OWNER: u32       = 0x04;
const FN_GET_BALANCE: u32     = 0x05;
const FN_INIT: u32            = 0x06;
const FN_PROPOSE_OWNER: u32   = 0x07;
const FN_ACCEPT_OWNER: u32    = 0x08;
const FN_REQUEST_WITHDRAW: u32 = 0x09;
const FN_EXECUTE_WITHDRAW: u32 = 0x0A;
const FN_CANCEL_WITHDRAW: u32  = 0x0B;

// ── Event Topics ────────────────────────────────────────────────────────────
// Topic: Deposit(sender, amount)
const TOPIC_DEPOSIT: [u8; 32] = [
    0x44, 0x65, 0x70, 0x6F, 0x73, 0x69, 0x74, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// Topic: Withdraw(to, amount)
const TOPIC_WITHDRAW: [u8; 32] = [
    0x57, 0x69, 0x74, 0x68, 0x64, 0x72, 0x61, 0x77,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// Topic: OwnershipTransferred(old_owner, new_owner)
const TOPIC_OWNERSHIP_TRANSFERRED: [u8; 32] = [
    0x4F, 0x77, 0x6E, 0x65, 0x72, 0x73, 0x68, 0x69,
    0x70, 0x54, 0x72, 0x61, 0x6E, 0x73, 0x66, 0x65,
    0x72, 0x72, 0x65, 0x64, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// Topic: OwnershipProposed(current_owner, proposed_owner)
const TOPIC_OWNERSHIP_PROPOSED: [u8; 32] = [
    0x4F, 0x77, 0x6E, 0x50, 0x72, 0x6F, 0x70, 0x6F,
    0x73, 0x65, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// Topic: WithdrawRequested(to, amount, unlock_time)
const TOPIC_WITHDRAW_REQUESTED: [u8; 32] = [
    0x57, 0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
    0x74, 0x65, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// Topic: WithdrawCancelled(to, amount)
const TOPIC_WITHDRAW_CANCELLED: [u8; 32] = [
    0x57, 0x64, 0x43, 0x61, 0x6E, 0x63, 0x65, 0x6C,
    0x6C, 0x65, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// ── Helpers ─────────────────────────────────────────────────────────────────

fn get_owner() -> [u8; 20] {
    let key = storage_slot(SLOT_OWNER, &[]);
    let (val, exists) = sload(&key);
    if exists {
        value_to_address(&val)
    } else {
        [0u8; 20]
    }
}

fn set_owner(new_owner: &[u8; 20]) {
    let key = storage_slot(SLOT_OWNER, &[]);
    sstore(&key, &address_to_value(new_owner));
}

fn get_pending_owner() -> [u8; 20] {
    let key = storage_slot(SLOT_PENDING_OWNER, &[]);
    let (val, exists) = sload(&key);
    if exists {
        value_to_address(&val)
    } else {
        [0u8; 20]
    }
}

fn set_pending_owner(addr: &[u8; 20]) {
    let key = storage_slot(SLOT_PENDING_OWNER, &[]);
    sstore(&key, &address_to_value(addr));
}

fn clear_pending_owner() {
    set_pending_owner(&[0u8; 20]);
}

fn get_pending_withdraw_to() -> [u8; 20] {
    let key = storage_slot(SLOT_PENDING_TO, &[]);
    let (val, exists) = sload(&key);
    if exists {
        value_to_address(&val)
    } else {
        [0u8; 20]
    }
}

fn set_pending_withdraw_to(addr: &[u8; 20]) {
    let key = storage_slot(SLOT_PENDING_TO, &[]);
    sstore(&key, &address_to_value(addr));
}

fn get_pending_withdraw_amount() -> u64 {
    let key = storage_slot(SLOT_PENDING_AMOUNT, &[]);
    let (val, exists) = sload(&key);
    if exists {
        u64::from_le_bytes([val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7]])
    } else {
        0
    }
}

fn set_pending_withdraw_amount(amount: u64) {
    let key = storage_slot(SLOT_PENDING_AMOUNT, &[]);
    let mut val = [0u8; 32];
    val[0..8].copy_from_slice(&amount.to_le_bytes());
    sstore(&key, &val);
}

fn get_pending_withdraw_unlock() -> u64 {
    let key = storage_slot(SLOT_PENDING_UNLOCK, &[]);
    let (val, exists) = sload(&key);
    if exists {
        u64::from_le_bytes([val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7]])
    } else {
        0
    }
}

fn set_pending_withdraw_unlock(timestamp: u64) {
    let key = storage_slot(SLOT_PENDING_UNLOCK, &[]);
    let mut val = [0u8; 32];
    val[0..8].copy_from_slice(&timestamp.to_le_bytes());
    sstore(&key, &val);
}

fn clear_pending_withdraw() {
    set_pending_withdraw_to(&[0u8; 20]);
    set_pending_withdraw_amount(0);
    set_pending_withdraw_unlock(0);
}

/// Reject ALL operations when owner is zero address.
/// Owner must be initialized via FN_INIT before any privileged operation.
fn require_owner(caller: &[u8; 20]) {
    let owner = get_owner();
    if owner == [0u8; 20] {
        halt(2); // No owner set — reject all operations
    }
    if caller != &owner {
        halt(2); // Unauthorized
    }
}

// ── Entry Point ─────────────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn _start() {
    let selector = calldata_selector();

    match selector {
        FN_DEPOSIT => {
            // Deposit native BRC tokens into the treasury
            let sender = msg_sender();
            let amount = msg_value();
            if amount == 0 {
                halt(6); // Cannot deposit 0
            }

            // Emit Deposit(sender, amount)
            let mut sender_topic = [0u8; 32];
            sender_topic[0..20].copy_from_slice(&sender);
            let data = amount.to_le_bytes();
            emit_log(&[TOPIC_DEPOSIT, sender_topic], &data);

            write_output(&[1u8; 1]); // Return true
        }

        FN_WITHDRAW => {
            // Instant withdrawal — owner only, capped at MAX_INSTANT_WITHDRAW
            enter_reentrancy_lock();

            let caller = msg_sender();
            require_owner(&caller);

            let to = calldata_address(4);
            let amount = calldata_u64(24);
            if amount == 0 {
                exit_reentrancy_lock();
                halt(7); // Cannot withdraw 0
            }
            if amount > MAX_INSTANT_WITHDRAW {
                exit_reentrancy_lock();
                halt(10); // Exceeds instant limit — use timelock path
            }

            transfer_native(&to, amount);

            // Emit Withdraw(to, amount)
            let mut to_topic = [0u8; 32];
            to_topic[0..20].copy_from_slice(&to);
            let data = amount.to_le_bytes();
            emit_log(&[TOPIC_WITHDRAW, to_topic], &data);

            write_output(&[1u8; 1]);
            exit_reentrancy_lock();
        }

        // ── Two-step ownership transfer ─────────────────────────────────

        FN_PROPOSE_OWNER => {
            // Step 1: Current owner proposes a new owner
            let caller = msg_sender();
            require_owner(&caller);

            let proposed = calldata_address(4);
            if proposed == [0u8; 20] {
                halt(9); // Cannot propose zero address
            }

            set_pending_owner(&proposed);

            // Emit OwnershipProposed(current_owner, proposed_owner)
            let mut current_topic = [0u8; 32];
            current_topic[0..20].copy_from_slice(&caller);
            let mut proposed_topic = [0u8; 32];
            proposed_topic[0..20].copy_from_slice(&proposed);
            emit_log(&[TOPIC_OWNERSHIP_PROPOSED, current_topic, proposed_topic], &[]);

            write_output(&[1u8; 1]);
        }

        FN_ACCEPT_OWNER => {
            // Step 2: Proposed owner accepts ownership
            let caller = msg_sender();
            let pending = get_pending_owner();

            if pending == [0u8; 20] {
                halt(11); // No pending owner proposal
            }
            if caller != pending {
                halt(2); // Only proposed owner can accept
            }

            let old_owner = get_owner();
            set_owner(&caller);
            clear_pending_owner();

            // Emit OwnershipTransferred(old_owner, new_owner)
            let mut old_topic = [0u8; 32];
            old_topic[0..20].copy_from_slice(&old_owner);
            let mut new_topic = [0u8; 32];
            new_topic[0..20].copy_from_slice(&caller);
            emit_log(&[TOPIC_OWNERSHIP_TRANSFERRED, old_topic, new_topic], &[]);

            write_output(&[1u8; 1]);
        }

        // ── Timelocked withdrawal path ──────────────────────────────────

        FN_REQUEST_WITHDRAW => {
            // Owner requests a withdrawal — starts the timelock countdown
            enter_reentrancy_lock();

            let caller = msg_sender();
            require_owner(&caller);

            // Reject if there is already a pending withdrawal
            let existing_amount = get_pending_withdraw_amount();
            if existing_amount != 0 {
                exit_reentrancy_lock();
                halt(12); // Pending withdrawal already exists — cancel first
            }

            let to = calldata_address(4);
            let amount = calldata_u64(24);
            if amount == 0 {
                exit_reentrancy_lock();
                halt(7); // Cannot withdraw 0
            }
            if to == [0u8; 20] {
                exit_reentrancy_lock();
                halt(13); // Cannot withdraw to zero address
            }

            let now = block_timestamp();
            let unlock_time = match now.checked_add(TIMELOCK_SECONDS) {
                Some(t) => t,
                None => {
                    exit_reentrancy_lock();
                    halt(16); // Timelock overflow — timestamp too large
                }
            };

            set_pending_withdraw_to(&to);
            set_pending_withdraw_amount(amount);
            set_pending_withdraw_unlock(unlock_time);

            // Emit WithdrawRequested(to, amount, unlock_time)
            let mut to_topic = [0u8; 32];
            to_topic[0..20].copy_from_slice(&to);
            let mut data = [0u8; 16];
            data[0..8].copy_from_slice(&amount.to_le_bytes());
            data[8..16].copy_from_slice(&unlock_time.to_le_bytes());
            emit_log(&[TOPIC_WITHDRAW_REQUESTED, to_topic], &data);

            write_output(&[1u8; 1]);
            exit_reentrancy_lock();
        }

        FN_EXECUTE_WITHDRAW => {
            // Anyone can execute after the timelock expires
            enter_reentrancy_lock();

            let to = get_pending_withdraw_to();
            let amount = get_pending_withdraw_amount();
            let unlock_time = get_pending_withdraw_unlock();

            if amount == 0 {
                exit_reentrancy_lock();
                halt(14); // No pending withdrawal
            }

            let now = block_timestamp();
            if now < unlock_time {
                exit_reentrancy_lock();
                halt(15); // Timelock not yet expired
            }

            // Clear pending state before transfer (prevent reentrancy)
            clear_pending_withdraw();

            transfer_native(&to, amount);

            // Emit Withdraw(to, amount)
            let mut to_topic = [0u8; 32];
            to_topic[0..20].copy_from_slice(&to);
            let data = amount.to_le_bytes();
            emit_log(&[TOPIC_WITHDRAW, to_topic], &data);

            write_output(&[1u8; 1]);
            exit_reentrancy_lock();
        }

        FN_CANCEL_WITHDRAW => {
            // Owner cancels a pending timelocked withdrawal
            enter_reentrancy_lock();

            let caller = msg_sender();
            require_owner(&caller);

            let to = get_pending_withdraw_to();
            let amount = get_pending_withdraw_amount();

            if amount == 0 {
                exit_reentrancy_lock();
                halt(14); // No pending withdrawal to cancel
            }

            clear_pending_withdraw();

            // Emit WithdrawCancelled(to, amount)
            let mut to_topic = [0u8; 32];
            to_topic[0..20].copy_from_slice(&to);
            let data = amount.to_le_bytes();
            emit_log(&[TOPIC_WITHDRAW_CANCELLED, to_topic], &data);

            write_output(&[1u8; 1]);
            exit_reentrancy_lock();
        }

        // ── Read-only queries ───────────────────────────────────────────

        FN_GET_OWNER => {
            let owner = get_owner();
            write_output(&owner);
        }
        FN_GET_BALANCE => {
            write_output(&0u64.to_le_bytes());
        }

        // ── One-time initialization ─────────────────────────────────────

        FN_INIT => {
            let owner = get_owner();
            if owner != [0u8; 20] {
                halt(8); // Already initialized
            }
            // Use msg_sender() instead of calldata for the initial owner.
            // Reading from calldata allows an attacker to set an arbitrary owner
            // if they front-run the init transaction.
            let new_owner = msg_sender();
            if new_owner == [0u8; 20] {
                halt(9); // Cannot set zero address as owner
            }
            set_owner(&new_owner);

            // Emit OwnershipTransferred(zero, new_owner)
            let old_topic = [0u8; 32];
            let mut new_topic = [0u8; 32];
            new_topic[0..20].copy_from_slice(&new_owner);
            emit_log(&[TOPIC_OWNERSHIP_TRANSFERRED, old_topic, new_topic], &[]);

            write_output(&[1u8; 1]);
        }

        _ => halt(1), // Unknown selector
    }

    halt(0); // Standard successful exit
}
