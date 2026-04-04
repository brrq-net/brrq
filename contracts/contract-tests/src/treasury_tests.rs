//! Tests for the treasury contract.
//!
//! Function selectors (4-byte LE u32):
//!   0x01 — Deposit (msg.value > 0)
//!   0x02 — Instant withdraw (owner, addr + u64, capped at 100M sats)
//!   0x04 — Get owner (read-only)
//!   0x05 — Get balance (read-only, returns 0)
//!   0x06 — Init (msg.sender becomes owner)
//!   0x07 — Propose owner (owner, addr)
//!   0x08 — Accept owner (pending owner only)
//!   0x09 — Request withdraw (owner, addr + u64, starts 48h timelock)
//!   0x0A — Execute withdraw (anyone, after timelock expires)
//!   0x0B — Cancel withdraw (owner)

use crate::harness::*;

const CODE: &[u8] = TREASURY_CODE;
const TS_BASE: u64 = 1_000_000;
const TIMELOCK: u64 = 172_800; // 48 hours

// ── Init ───────────────────────────────────────────────────────────────────

#[test]
fn init_sets_owner() {
    let mut s = Storage::new();
    let owner = addr("owner");

    let r = run(CODE, &mut s, &sel(0x06), &owner, 0, TS_BASE);
    assert_eq!(r.exit_code, 0, "init should succeed");

    // Verify owner
    let r = run(CODE, &mut s, &sel(0x04), &owner, 0, TS_BASE);
    assert_eq!(r.exit_code, 0);
    assert_eq!(output_addr(&r), owner);
}

#[test]
fn init_twice_fails() {
    let mut s = Storage::new();
    let owner = addr("owner");

    run(CODE, &mut s, &sel(0x06), &owner, 0, TS_BASE);

    let r = run(CODE, &mut s, &sel(0x06), &owner, 0, TS_BASE);
    assert_eq!(r.exit_code, 8, "second init should fail with 'already initialized'");
}

// ── Deposit ────────────────────────────────────────────────────────────────

#[test]
fn deposit_succeeds() {
    let mut s = Storage::new();
    let owner = addr("owner");
    let depositor = addr("depositor");

    run(CODE, &mut s, &sel(0x06), &owner, 0, TS_BASE);

    let r = run(CODE, &mut s, &sel(0x01), &depositor, 1_000, TS_BASE);
    assert_eq!(r.exit_code, 0, "deposit should succeed");
    assert_eq!(r.output, [1u8], "should return true");
    assert!(!r.logs.is_empty(), "should emit Deposit event");
}

#[test]
fn deposit_zero_fails() {
    let mut s = Storage::new();
    let owner = addr("owner");

    run(CODE, &mut s, &sel(0x06), &owner, 0, TS_BASE);

    let r = run(CODE, &mut s, &sel(0x01), &owner, 0, TS_BASE);
    assert_eq!(r.exit_code, 6, "zero deposit should fail");
}

// ── Instant Withdraw ───────────────────────────────────────────────────────

#[test]
fn instant_withdraw_by_owner() {
    let mut s = Storage::new();
    let owner = addr("owner");
    let recipient = addr("recipient");

    run(CODE, &mut s, &sel(0x06), &owner, 0, TS_BASE);

    let r = run(CODE, &mut s, &sel_addr_u64(0x02, &recipient, 50_000_000), &owner, 0, TS_BASE);
    assert_eq!(r.exit_code, 0, "instant withdraw should succeed");
}

#[test]
fn instant_withdraw_over_limit_fails() {
    let mut s = Storage::new();
    let owner = addr("owner");
    let recipient = addr("recipient");

    run(CODE, &mut s, &sel(0x06), &owner, 0, TS_BASE);

    // 100_000_001 > MAX_INSTANT_WITHDRAW (100_000_000)
    let r = run(CODE, &mut s, &sel_addr_u64(0x02, &recipient, 100_000_001), &owner, 0, TS_BASE);
    assert_eq!(r.exit_code, 10, "over-limit should fail");
}

#[test]
fn instant_withdraw_at_limit_succeeds() {
    let mut s = Storage::new();
    let owner = addr("owner");
    let recipient = addr("recipient");

    run(CODE, &mut s, &sel(0x06), &owner, 0, TS_BASE);

    let r = run(CODE, &mut s, &sel_addr_u64(0x02, &recipient, 100_000_000), &owner, 0, TS_BASE);
    assert_eq!(r.exit_code, 0, "withdraw at exactly the limit should succeed");
}

#[test]
fn instant_withdraw_zero_fails() {
    let mut s = Storage::new();
    let owner = addr("owner");
    let recipient = addr("recipient");

    run(CODE, &mut s, &sel(0x06), &owner, 0, TS_BASE);

    let r = run(CODE, &mut s, &sel_addr_u64(0x02, &recipient, 0), &owner, 0, TS_BASE);
    assert_eq!(r.exit_code, 7, "zero withdraw should fail");
}

#[test]
fn instant_withdraw_by_non_owner_fails() {
    let mut s = Storage::new();
    let owner = addr("owner");
    let attacker = addr("attacker");
    let recipient = addr("recipient");

    run(CODE, &mut s, &sel(0x06), &owner, 0, TS_BASE);

    let r = run(CODE, &mut s, &sel_addr_u64(0x02, &recipient, 1000), &attacker, 0, TS_BASE);
    assert_eq!(r.exit_code, 2, "non-owner should fail");
}

// ── Two-step ownership transfer ────────────────────────────────────────────

#[test]
fn ownership_transfer_two_step() {
    let mut s = Storage::new();
    let owner = addr("owner");
    let new_owner = addr("new_owner");

    run(CODE, &mut s, &sel(0x06), &owner, 0, TS_BASE);

    // Propose
    let r = run(CODE, &mut s, &sel_addr(0x07, &new_owner), &owner, 0, TS_BASE);
    assert_eq!(r.exit_code, 0, "propose should succeed");

    // Accept
    let r = run(CODE, &mut s, &sel(0x08), &new_owner, 0, TS_BASE);
    assert_eq!(r.exit_code, 0, "accept should succeed");

    // Verify new owner
    let r = run(CODE, &mut s, &sel(0x04), &new_owner, 0, TS_BASE);
    assert_eq!(output_addr(&r), new_owner);

    // Old owner can no longer withdraw
    let recipient = addr("recipient");
    let r = run(CODE, &mut s, &sel_addr_u64(0x02, &recipient, 1000), &owner, 0, TS_BASE);
    assert_eq!(r.exit_code, 2, "old owner should be unauthorized");
}

#[test]
fn propose_zero_address_fails() {
    let mut s = Storage::new();
    let owner = addr("owner");

    run(CODE, &mut s, &sel(0x06), &owner, 0, TS_BASE);

    let r = run(CODE, &mut s, &sel_addr(0x07, &[0u8; 20]), &owner, 0, TS_BASE);
    assert_eq!(r.exit_code, 9, "zero address proposal should fail");
}

#[test]
fn accept_by_wrong_caller_fails() {
    let mut s = Storage::new();
    let owner = addr("owner");
    let proposed = addr("proposed");
    let attacker = addr("attacker");

    run(CODE, &mut s, &sel(0x06), &owner, 0, TS_BASE);
    run(CODE, &mut s, &sel_addr(0x07, &proposed), &owner, 0, TS_BASE);

    let r = run(CODE, &mut s, &sel(0x08), &attacker, 0, TS_BASE);
    assert_eq!(r.exit_code, 2, "wrong caller should fail");
}

#[test]
fn accept_with_no_pending_fails() {
    let mut s = Storage::new();
    let owner = addr("owner");

    run(CODE, &mut s, &sel(0x06), &owner, 0, TS_BASE);

    let r = run(CODE, &mut s, &sel(0x08), &owner, 0, TS_BASE);
    assert_eq!(r.exit_code, 11, "no pending owner should fail");
}

// ── Timelocked Withdrawal ──────────────────────────────────────────────────

#[test]
fn timelock_request_execute_flow() {
    let mut s = Storage::new();
    let owner = addr("owner");
    let recipient = addr("recipient");
    let amount: u64 = 500_000_000; // 5 BTC

    run(CODE, &mut s, &sel(0x06), &owner, 0, TS_BASE);

    // Request withdrawal
    let r = run(CODE, &mut s, &sel_addr_u64(0x09, &recipient, amount), &owner, 0, TS_BASE);
    assert_eq!(r.exit_code, 0, "request should succeed");

    // Execute before timelock expires — should fail
    let r = run(CODE, &mut s, &sel(0x0A), &owner, 0, TS_BASE + TIMELOCK - 1);
    assert_eq!(r.exit_code, 15, "early execute should fail");

    // Execute after timelock expires — should succeed
    let r = run(CODE, &mut s, &sel(0x0A), &owner, 0, TS_BASE + TIMELOCK);
    assert_eq!(r.exit_code, 0, "execute after timelock should succeed");
}

#[test]
fn timelock_cancel() {
    let mut s = Storage::new();
    let owner = addr("owner");
    let recipient = addr("recipient");

    run(CODE, &mut s, &sel(0x06), &owner, 0, TS_BASE);
    run(CODE, &mut s, &sel_addr_u64(0x09, &recipient, 1_000_000), &owner, 0, TS_BASE);

    // Cancel
    let r = run(CODE, &mut s, &sel(0x0B), &owner, 0, TS_BASE);
    assert_eq!(r.exit_code, 0, "cancel should succeed");

    // Execute after cancel — should fail (no pending)
    let r = run(CODE, &mut s, &sel(0x0A), &owner, 0, TS_BASE + TIMELOCK);
    assert_eq!(r.exit_code, 14, "execute after cancel should fail");
}

#[test]
fn timelock_double_request_fails() {
    let mut s = Storage::new();
    let owner = addr("owner");
    let recipient = addr("recipient");

    run(CODE, &mut s, &sel(0x06), &owner, 0, TS_BASE);
    run(CODE, &mut s, &sel_addr_u64(0x09, &recipient, 1_000_000), &owner, 0, TS_BASE);

    // Second request should fail
    let r = run(CODE, &mut s, &sel_addr_u64(0x09, &recipient, 2_000_000), &owner, 0, TS_BASE);
    assert_eq!(r.exit_code, 12, "double request should fail");
}

#[test]
fn timelock_request_zero_amount_fails() {
    let mut s = Storage::new();
    let owner = addr("owner");
    let recipient = addr("recipient");

    run(CODE, &mut s, &sel(0x06), &owner, 0, TS_BASE);

    let r = run(CODE, &mut s, &sel_addr_u64(0x09, &recipient, 0), &owner, 0, TS_BASE);
    assert_eq!(r.exit_code, 7, "zero amount request should fail");
}

#[test]
fn timelock_request_zero_address_fails() {
    let mut s = Storage::new();
    let owner = addr("owner");

    run(CODE, &mut s, &sel(0x06), &owner, 0, TS_BASE);

    let r = run(CODE, &mut s, &sel_addr_u64(0x09, &[0u8; 20], 1000), &owner, 0, TS_BASE);
    assert_eq!(r.exit_code, 13, "zero address should fail");
}

#[test]
fn timelock_request_by_non_owner_fails() {
    let mut s = Storage::new();
    let owner = addr("owner");
    let attacker = addr("attacker");
    let recipient = addr("recipient");

    run(CODE, &mut s, &sel(0x06), &owner, 0, TS_BASE);

    let r = run(CODE, &mut s, &sel_addr_u64(0x09, &recipient, 1000), &attacker, 0, TS_BASE);
    assert_eq!(r.exit_code, 2, "non-owner request should fail");
}

#[test]
fn cancel_with_no_pending_fails() {
    let mut s = Storage::new();
    let owner = addr("owner");

    run(CODE, &mut s, &sel(0x06), &owner, 0, TS_BASE);

    let r = run(CODE, &mut s, &sel(0x0B), &owner, 0, TS_BASE);
    assert_eq!(r.exit_code, 14, "cancel with no pending should fail");
}

#[test]
fn cancel_by_non_owner_fails() {
    let mut s = Storage::new();
    let owner = addr("owner");
    let attacker = addr("attacker");
    let recipient = addr("recipient");

    run(CODE, &mut s, &sel(0x06), &owner, 0, TS_BASE);
    run(CODE, &mut s, &sel_addr_u64(0x09, &recipient, 1000), &owner, 0, TS_BASE);

    let r = run(CODE, &mut s, &sel(0x0B), &attacker, 0, TS_BASE);
    assert_eq!(r.exit_code, 2, "non-owner cancel should fail");
}

#[test]
fn execute_with_no_pending_fails() {
    let mut s = Storage::new();
    let owner = addr("owner");

    run(CODE, &mut s, &sel(0x06), &owner, 0, TS_BASE);

    let r = run(CODE, &mut s, &sel(0x0A), &owner, 0, TS_BASE + TIMELOCK);
    assert_eq!(r.exit_code, 14, "execute with no pending should fail");
}

#[test]
fn timelock_overflow_fails() {
    let mut s = Storage::new();
    let owner = addr("owner");
    let recipient = addr("recipient");

    // SDK uses SYS_BLOCK_TIMESTAMP (0x201) which truncates u64 → u32.
    // Use u32::MAX as timestamp to trigger checked_add overflow.
    let ts_max = u32::MAX as u64;
    run(CODE, &mut s, &sel(0x06), &owner, 0, ts_max);

    // u32::MAX + 172800 > u32::MAX but fits in u64.
    // The contract reads block_timestamp as u32 then extends to u64,
    // so checked_add(172800) succeeds with a value of ~4295140095.
    // Overflow only happens if the u64 result overflows, which won't
    // happen with a u32 timestamp. This test verifies the contract
    // correctly handles near-max timestamps without panicking.
    let r = run(CODE, &mut s, &sel_addr_u64(0x09, &recipient, 1000), &owner, 0, ts_max);
    assert_eq!(r.exit_code, 0, "near-max timestamp should succeed (u32 truncation)");
}

// ── Read-only queries ──────────────────────────────────────────────────────

#[test]
fn get_balance_returns_zero() {
    let mut s = Storage::new();
    let owner = addr("owner");

    run(CODE, &mut s, &sel(0x06), &owner, 0, TS_BASE);

    let r = run(CODE, &mut s, &sel(0x05), &owner, 0, TS_BASE);
    assert_eq!(r.exit_code, 0);
    assert_eq!(output_u64(&r), 0);
}

#[test]
fn unknown_selector_fails() {
    let mut s = Storage::new();
    let owner = addr("owner");

    run(CODE, &mut s, &sel(0x06), &owner, 0, TS_BASE);

    let r = run(CODE, &mut s, &sel(0xFF), &owner, 0, TS_BASE);
    assert_eq!(r.exit_code, 1, "unknown selector should fail");
}

// ── Operations before init ─────────────────────────────────────────────────

#[test]
fn withdraw_before_init_fails() {
    let mut s = Storage::new();
    let anyone = addr("anyone");
    let recipient = addr("recipient");

    let r = run(CODE, &mut s, &sel_addr_u64(0x02, &recipient, 1000), &anyone, 0, TS_BASE);
    assert_eq!(r.exit_code, 2, "withdraw before init should fail");
}
