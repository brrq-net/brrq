#![no_std]
#![no_main]

use brrq_contract_sdk::*;

// ── Storage Slot Prefixes ───────────────────────────────────────────────────
const SLOT_BALANCE: u32 = 0x00;
const SLOT_ALLOWANCE: u32 = 0x01;
const SLOT_TOTAL_SUPPLY: u32 = 0x02;

// ── Function Selectors ──────────────────────────────────────────────────────
const FN_TRANSFER: u32      = 0x01;
const FN_BALANCE_OF: u32    = 0x02;
const FN_APPROVE: u32       = 0x03;
const FN_TRANSFER_FROM: u32 = 0x04;
const FN_ALLOWANCE: u32     = 0x05;
const FN_TOTAL_SUPPLY: u32  = 0x06;
const FN_DEPOSIT: u32       = 0x0A;
const FN_WITHDRAW: u32      = 0x0B;

// ── Helpers ─────────────────────────────────────────────────────────────────

fn get_balance(addr: &[u8; 20]) -> u64 {
    let key = storage_slot(SLOT_BALANCE, addr);
    let (val, exists) = sload(&key);
    if exists { value_to_u64(&val) } else { 0 }
}

fn set_balance(addr: &[u8; 20], amount: u64) {
    let key = storage_slot(SLOT_BALANCE, addr);
    sstore(&key, &u64_to_value(amount));
}

fn get_allowance(owner: &[u8; 20], spender: &[u8; 20]) -> u64 {
    let mut combined = [0u8; 40];
    combined[0..20].copy_from_slice(owner);
    combined[20..40].copy_from_slice(spender);
    let key = storage_slot(SLOT_ALLOWANCE, &combined);
    let (val, exists) = sload(&key);
    if exists { value_to_u64(&val) } else { 0 }
}

fn set_allowance(owner: &[u8; 20], spender: &[u8; 20], amount: u64) {
    let mut combined = [0u8; 40];
    combined[0..20].copy_from_slice(owner);
    combined[20..40].copy_from_slice(spender);
    let key = storage_slot(SLOT_ALLOWANCE, &combined);
    sstore(&key, &u64_to_value(amount));
}

fn get_total_supply() -> u64 {
    let key = storage_slot(SLOT_TOTAL_SUPPLY, &[]);
    let (val, exists) = sload(&key);
    if exists { value_to_u64(&val) } else { 0 }
}

fn set_total_supply(amount: u64) {
    let key = storage_slot(SLOT_TOTAL_SUPPLY, &[]);
    sstore(&key, &u64_to_value(amount));
}

// ── Entry Point ─────────────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn _start() {
    let selector = calldata_selector();

    match selector {
        FN_TRANSFER => {
            let to = calldata_address(4);
            let amount = calldata_u64(24);
            let from = msg_sender();

            // Self-transfer guard: when from == to, skip balance writes since
            // the net effect is zero. Validate sufficient balance and emit the
            // event only.
            let from_balance = get_balance(&from);
            if from == to {
                if from_balance < amount {
                    halt(3); // Insufficient balance
                }
                // Net balance unchanged — no storage writes needed.
            } else {
                let new_from = match from_balance.checked_sub(amount) {
                    Some(v) => v,
                    None => halt(3), // Insufficient balance
                };
                let to_balance = get_balance(&to);
                let new_to = match to_balance.checked_add(amount) {
                    Some(v) => v,
                    None => halt(5), // Overflow
                };

                set_balance(&from, new_from);
                set_balance(&to, new_to);
            }

            let mut from_topic = [0u8; 32];
            from_topic[0..20].copy_from_slice(&from);
            let mut to_topic = [0u8; 32];
            to_topic[0..20].copy_from_slice(&to);
            let data = amount.to_le_bytes();
            emit_log(&[TOPIC_TRANSFER, from_topic, to_topic], &data);

            write_output(&[1u8; 1]); // Return true
        }
        FN_BALANCE_OF => {
            let addr = calldata_address(4);
            let bal = get_balance(&addr);
            write_output(&bal.to_le_bytes());
        }
        FN_APPROVE => {
            let spender = calldata_address(4);
            let amount = calldata_u64(24);
            let owner = msg_sender();

            set_allowance(&owner, &spender, amount);

            let mut owner_topic = [0u8; 32];
            owner_topic[0..20].copy_from_slice(&owner);
            let mut spender_topic = [0u8; 32];
            spender_topic[0..20].copy_from_slice(&spender);
            let data = amount.to_le_bytes();
            emit_log(&[TOPIC_APPROVAL, owner_topic, spender_topic], &data);

            write_output(&[1u8; 1]); // Return true
        }
        FN_TRANSFER_FROM => {
            let from = calldata_address(4);
            let to = calldata_address(24);
            let amount = calldata_u64(44);
            let spender = msg_sender();

            let allowed = get_allowance(&from, &spender);
            let new_allowed = match allowed.checked_sub(amount) {
                Some(v) => v,
                None => halt(4), // Insufficient allowance
            };

            // Self-transfer guard: skip balance writes when from == to.
            // Allowance is still consumed because the spender is exercising
            // their approved quota.
            let from_balance = get_balance(&from);
            if from == to {
                if from_balance < amount {
                    halt(3); // Insufficient balance
                }
                set_allowance(&from, &spender, new_allowed);
                // Net balance unchanged — no balance writes needed.
            } else {
                let new_from = match from_balance.checked_sub(amount) {
                    Some(v) => v,
                    None => halt(3), // Insufficient balance
                };
                let to_balance = get_balance(&to);
                let new_to = match to_balance.checked_add(amount) {
                    Some(v) => v,
                    None => halt(5), // Overflow
                };

                set_allowance(&from, &spender, new_allowed);
                set_balance(&from, new_from);
                set_balance(&to, new_to);
            }

            let mut from_topic = [0u8; 32];
            from_topic[0..20].copy_from_slice(&from);
            let mut to_topic = [0u8; 32];
            to_topic[0..20].copy_from_slice(&to);
            let data = amount.to_le_bytes();
            emit_log(&[TOPIC_TRANSFER, from_topic, to_topic], &data);

            write_output(&[1u8; 1]); // Return true
        }
        FN_ALLOWANCE => {
            let owner = calldata_address(4);
            let spender = calldata_address(24);
            let allowed = get_allowance(&owner, &spender);
            write_output(&allowed.to_le_bytes());
        }
        FN_TOTAL_SUPPLY => {
            let ts = get_total_supply();
            write_output(&ts.to_le_bytes());
        }
        FN_DEPOSIT => {
            let sender = msg_sender();
            let amount = msg_value();
            if amount == 0 { halt(6); } // Cannot deposit 0

            let sender_balance = get_balance(&sender);
            let new_sender_balance = match sender_balance.checked_add(amount) {
                Some(v) => v,
                None => halt(5),
            };

            let ts = get_total_supply();
            let new_ts = match ts.checked_add(amount) {
                Some(v) => v,
                None => halt(5),
            };

            set_balance(&sender, new_sender_balance);
            set_total_supply(new_ts);

            // Emit Transfer(ZERO, sender, amount)
            let mut from_topic = [0u8; 32];
            let mut to_topic = [0u8; 32];
            to_topic[0..20].copy_from_slice(&sender);
            let data = amount.to_le_bytes();
            emit_log(&[TOPIC_TRANSFER, from_topic, to_topic], &data);

            write_output(&[1u8; 1]); // Return true
        }
        FN_WITHDRAW => {
            // Defense-in-depth reentrancy guard on withdrawal path.
            // Current VM prevents reentrancy, but this protects against future VM evolution.
            enter_reentrancy_lock();
            let sender = msg_sender();
            let amount = calldata_u64(4);
            if amount == 0 { exit_reentrancy_lock(); halt(7); } // Cannot withdraw 0

            let sender_balance = get_balance(&sender);
            let new_sender_balance = match sender_balance.checked_sub(amount) {
                Some(v) => v,
                None => halt(3), // Insufficient balance
            };

            let ts = get_total_supply();
            let new_ts = match ts.checked_sub(amount) {
                Some(v) => v,
                None => halt(3), // Cannot underflow total supply
            };

            set_balance(&sender, new_sender_balance);
            set_total_supply(new_ts);

            // Call to VM to release base layer funds
            transfer_native(&sender, amount);

            // Emit Transfer(sender, ZERO, amount)
            let mut from_topic = [0u8; 32];
            from_topic[0..20].copy_from_slice(&sender);
            let mut to_topic = [0u8; 32];
            let data = amount.to_le_bytes();
            emit_log(&[TOPIC_TRANSFER, from_topic, to_topic], &data);

            write_output(&[1u8; 1]); // Return true
            exit_reentrancy_lock();
        }
        _ => halt(1), // Unknown selector
    }

    halt(0); // Success
}
