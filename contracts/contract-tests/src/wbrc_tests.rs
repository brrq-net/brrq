//! Tests for the WBRC (Wrapped BRC) token contract.
//!
//! Function selectors (4-byte LE u32):
//!   0x01 — Transfer (addr to + u64 amount)
//!   0x02 — Balance of (addr)
//!   0x03 — Approve (addr spender + u64 amount)
//!   0x04 — Transfer from (addr from + addr to + u64 amount)
//!   0x05 — Allowance (addr owner + addr spender)
//!   0x06 — Total supply
//!   0x0A — Deposit (msg.value → mint)
//!   0x0B — Withdraw (u64 amount → burn + native transfer)

use crate::harness::*;

const CODE: &[u8] = WBRC_CODE;
const TS: u64 = 1_000_000;

// ── Deposit / Mint ─────────────────────────────────────────────────────────

#[test]
fn deposit_mints_tokens() {
    let mut s = Storage::new();
    let alice = addr("alice");

    let r = run(CODE, &mut s, &sel(0x0A), &alice, 1000, TS);
    assert_eq!(r.exit_code, 0, "deposit should succeed");
    assert_eq!(r.output, [1u8]);

    // Check balance
    let r = run(CODE, &mut s, &sel_addr(0x02, &alice), &alice, 0, TS);
    assert_eq!(r.exit_code, 0);
    assert_eq!(output_u64(&r), 1000);

    // Check total supply
    let r = run(CODE, &mut s, &sel(0x06), &alice, 0, TS);
    assert_eq!(r.exit_code, 0);
    assert_eq!(output_u64(&r), 1000);
}

#[test]
fn deposit_zero_fails() {
    let mut s = Storage::new();
    let alice = addr("alice");

    let r = run(CODE, &mut s, &sel(0x0A), &alice, 0, TS);
    assert_eq!(r.exit_code, 6, "zero deposit should fail");
}

#[test]
fn multiple_deposits_accumulate() {
    let mut s = Storage::new();
    let alice = addr("alice");

    run(CODE, &mut s, &sel(0x0A), &alice, 500, TS);
    run(CODE, &mut s, &sel(0x0A), &alice, 300, TS);

    let r = run(CODE, &mut s, &sel_addr(0x02, &alice), &alice, 0, TS);
    assert_eq!(output_u64(&r), 800);

    let r = run(CODE, &mut s, &sel(0x06), &alice, 0, TS);
    assert_eq!(output_u64(&r), 800);
}

// ── Transfer ───────────────────────────────────────────────────────────────

#[test]
fn transfer_moves_tokens() {
    let mut s = Storage::new();
    let alice = addr("alice");
    let bob = addr("bob");

    // Mint 1000 to alice
    run(CODE, &mut s, &sel(0x0A), &alice, 1000, TS);

    // Transfer 400 to bob
    let r = run(CODE, &mut s, &sel_addr_u64(0x01, &bob, 400), &alice, 0, TS);
    assert_eq!(r.exit_code, 0, "transfer should succeed");
    assert!(!r.logs.is_empty(), "should emit Transfer event");

    // Check balances
    let r = run(CODE, &mut s, &sel_addr(0x02, &alice), &alice, 0, TS);
    assert_eq!(output_u64(&r), 600);

    let r = run(CODE, &mut s, &sel_addr(0x02, &bob), &alice, 0, TS);
    assert_eq!(output_u64(&r), 400);
}

#[test]
fn transfer_insufficient_balance_fails() {
    let mut s = Storage::new();
    let alice = addr("alice");
    let bob = addr("bob");

    run(CODE, &mut s, &sel(0x0A), &alice, 100, TS);

    let r = run(CODE, &mut s, &sel_addr_u64(0x01, &bob, 200), &alice, 0, TS);
    assert_eq!(r.exit_code, 3, "insufficient balance should fail");
}

#[test]
fn self_transfer_succeeds() {
    let mut s = Storage::new();
    let alice = addr("alice");

    run(CODE, &mut s, &sel(0x0A), &alice, 1000, TS);

    // Transfer to self
    let r = run(CODE, &mut s, &sel_addr_u64(0x01, &alice, 500), &alice, 0, TS);
    assert_eq!(r.exit_code, 0, "self-transfer should succeed");

    // Balance unchanged
    let r = run(CODE, &mut s, &sel_addr(0x02, &alice), &alice, 0, TS);
    assert_eq!(output_u64(&r), 1000);
}

#[test]
fn self_transfer_over_balance_fails() {
    let mut s = Storage::new();
    let alice = addr("alice");

    run(CODE, &mut s, &sel(0x0A), &alice, 100, TS);

    let r = run(CODE, &mut s, &sel_addr_u64(0x01, &alice, 200), &alice, 0, TS);
    assert_eq!(r.exit_code, 3, "self-transfer over balance should fail");
}

// ── Approve / Allowance ────────────────────────────────────────────────────

#[test]
fn approve_sets_allowance() {
    let mut s = Storage::new();
    let alice = addr("alice");
    let bob = addr("bob");

    let r = run(CODE, &mut s, &sel_addr_u64(0x03, &bob, 500), &alice, 0, TS);
    assert_eq!(r.exit_code, 0, "approve should succeed");

    // Check allowance
    let r = run(CODE, &mut s, &sel_addr_addr(0x05, &alice, &bob), &alice, 0, TS);
    assert_eq!(r.exit_code, 0);
    assert_eq!(output_u64(&r), 500);
}

#[test]
fn approve_overwrites_previous() {
    let mut s = Storage::new();
    let alice = addr("alice");
    let bob = addr("bob");

    run(CODE, &mut s, &sel_addr_u64(0x03, &bob, 500), &alice, 0, TS);
    run(CODE, &mut s, &sel_addr_u64(0x03, &bob, 200), &alice, 0, TS);

    let r = run(CODE, &mut s, &sel_addr_addr(0x05, &alice, &bob), &alice, 0, TS);
    assert_eq!(output_u64(&r), 200);
}

// ── Transfer From ──────────────────────────────────────────────────────────

#[test]
fn transfer_from_with_allowance() {
    let mut s = Storage::new();
    let alice = addr("alice");
    let bob = addr("bob");
    let charlie = addr("charlie");

    // Mint 1000 to alice
    run(CODE, &mut s, &sel(0x0A), &alice, 1000, TS);

    // Alice approves bob for 500
    run(CODE, &mut s, &sel_addr_u64(0x03, &bob, 500), &alice, 0, TS);

    // Bob transfers 300 from alice to charlie
    let r = run(
        CODE, &mut s,
        &sel_addr_addr_u64(0x04, &alice, &charlie, 300),
        &bob, 0, TS,
    );
    assert_eq!(r.exit_code, 0, "transferFrom should succeed");

    // Check balances
    let r = run(CODE, &mut s, &sel_addr(0x02, &alice), &alice, 0, TS);
    assert_eq!(output_u64(&r), 700);

    let r = run(CODE, &mut s, &sel_addr(0x02, &charlie), &alice, 0, TS);
    assert_eq!(output_u64(&r), 300);

    // Check remaining allowance
    let r = run(CODE, &mut s, &sel_addr_addr(0x05, &alice, &bob), &alice, 0, TS);
    assert_eq!(output_u64(&r), 200);
}

#[test]
fn transfer_from_exceeds_allowance_fails() {
    let mut s = Storage::new();
    let alice = addr("alice");
    let bob = addr("bob");
    let charlie = addr("charlie");

    run(CODE, &mut s, &sel(0x0A), &alice, 1000, TS);
    run(CODE, &mut s, &sel_addr_u64(0x03, &bob, 100), &alice, 0, TS);

    let r = run(
        CODE, &mut s,
        &sel_addr_addr_u64(0x04, &alice, &charlie, 200),
        &bob, 0, TS,
    );
    assert_eq!(r.exit_code, 4, "exceeding allowance should fail");
}

#[test]
fn transfer_from_exceeds_balance_fails() {
    let mut s = Storage::new();
    let alice = addr("alice");
    let bob = addr("bob");
    let charlie = addr("charlie");

    run(CODE, &mut s, &sel(0x0A), &alice, 100, TS);
    run(CODE, &mut s, &sel_addr_u64(0x03, &bob, 500), &alice, 0, TS);

    let r = run(
        CODE, &mut s,
        &sel_addr_addr_u64(0x04, &alice, &charlie, 200),
        &bob, 0, TS,
    );
    assert_eq!(r.exit_code, 3, "exceeding balance should fail");
}

#[test]
fn transfer_from_self_transfer() {
    let mut s = Storage::new();
    let alice = addr("alice");
    let bob = addr("bob");

    run(CODE, &mut s, &sel(0x0A), &alice, 1000, TS);
    run(CODE, &mut s, &sel_addr_u64(0x03, &bob, 500), &alice, 0, TS);

    // Bob transfers 200 from alice to alice (self-transfer)
    let r = run(
        CODE, &mut s,
        &sel_addr_addr_u64(0x04, &alice, &alice, 200),
        &bob, 0, TS,
    );
    assert_eq!(r.exit_code, 0, "self-transfer via transferFrom should succeed");

    // Balance unchanged
    let r = run(CODE, &mut s, &sel_addr(0x02, &alice), &alice, 0, TS);
    assert_eq!(output_u64(&r), 1000);

    // Allowance still consumed
    let r = run(CODE, &mut s, &sel_addr_addr(0x05, &alice, &bob), &alice, 0, TS);
    assert_eq!(output_u64(&r), 300);
}

// ── Withdraw / Burn ────────────────────────────────────────────────────────

#[test]
fn withdraw_burns_tokens() {
    let mut s = Storage::new();
    let alice = addr("alice");

    run(CODE, &mut s, &sel(0x0A), &alice, 1000, TS);

    let r = run(CODE, &mut s, &sel_u64(0x0B, 400), &alice, 0, TS);
    assert_eq!(r.exit_code, 0, "withdraw should succeed");

    // Balance decreased
    let r = run(CODE, &mut s, &sel_addr(0x02, &alice), &alice, 0, TS);
    assert_eq!(output_u64(&r), 600);

    // Total supply decreased
    let r = run(CODE, &mut s, &sel(0x06), &alice, 0, TS);
    assert_eq!(output_u64(&r), 600);
}

#[test]
fn withdraw_zero_fails() {
    let mut s = Storage::new();
    let alice = addr("alice");

    run(CODE, &mut s, &sel(0x0A), &alice, 1000, TS);

    let r = run(CODE, &mut s, &sel_u64(0x0B, 0), &alice, 0, TS);
    assert_eq!(r.exit_code, 7, "zero withdraw should fail");
}

#[test]
fn withdraw_insufficient_balance_fails() {
    let mut s = Storage::new();
    let alice = addr("alice");

    run(CODE, &mut s, &sel(0x0A), &alice, 100, TS);

    let r = run(CODE, &mut s, &sel_u64(0x0B, 200), &alice, 0, TS);
    assert_eq!(r.exit_code, 3, "insufficient balance should fail");
}

// ── Overflow protection ────────────────────────────────────────────────────

#[test]
fn deposit_overflow_fails() {
    let mut s = Storage::new();
    let alice = addr("alice");

    // Deposit near-max
    run(CODE, &mut s, &sel(0x0A), &alice, u64::MAX - 1, TS);

    // Second deposit should overflow
    let r = run(CODE, &mut s, &sel(0x0A), &alice, 2, TS);
    assert_eq!(r.exit_code, 5, "balance overflow should fail");
}

#[test]
fn total_supply_overflow_on_deposit_fails() {
    let mut s = Storage::new();
    let alice = addr("alice");
    let bob = addr("bob");

    // Deposit near-max to bob
    run(CODE, &mut s, &sel(0x0A), &bob, u64::MAX - 1, TS);

    // Second deposit pushes total supply over u64::MAX
    let r = run(CODE, &mut s, &sel(0x0A), &alice, 2, TS);
    assert_eq!(r.exit_code, 5, "total supply overflow should fail");
}

#[test]
fn max_balance_transfer_succeeds() {
    let mut s = Storage::new();
    let alice = addr("alice");
    let bob = addr("bob");

    // Total supply = MAX/2 + 1 + MAX/2 = MAX (fits exactly)
    let bob_amount = (u64::MAX / 2) + 1;
    let alice_amount = u64::MAX / 2;
    run(CODE, &mut s, &sel(0x0A), &bob, bob_amount, TS);
    run(CODE, &mut s, &sel(0x0A), &alice, alice_amount, TS);

    // Transfer all of alice's tokens to bob — sum is exactly MAX, no overflow
    let r = run(CODE, &mut s, &sel_addr_u64(0x01, &bob, alice_amount), &alice, 0, TS);
    assert_eq!(r.exit_code, 0, "transfer up to max should succeed");

    let r = run(CODE, &mut s, &sel_addr(0x02, &bob), &alice, 0, TS);
    assert_eq!(output_u64(&r), u64::MAX);
}

// ── Edge cases ─────────────────────────────────────────────────────────────

#[test]
fn unknown_selector_fails() {
    let mut s = Storage::new();
    let alice = addr("alice");

    let r = run(CODE, &mut s, &sel(0xFF), &alice, 0, TS);
    assert_eq!(r.exit_code, 1, "unknown selector should fail");
}

#[test]
fn total_supply_initially_zero() {
    let mut s = Storage::new();
    let alice = addr("alice");

    let r = run(CODE, &mut s, &sel(0x06), &alice, 0, TS);
    assert_eq!(r.exit_code, 0);
    assert_eq!(output_u64(&r), 0);
}

#[test]
fn balance_of_nonexistent_is_zero() {
    let mut s = Storage::new();
    let alice = addr("alice");
    let nobody = addr("nobody");

    let r = run(CODE, &mut s, &sel_addr(0x02, &nobody), &alice, 0, TS);
    assert_eq!(r.exit_code, 0);
    assert_eq!(output_u64(&r), 0);
}

#[test]
fn allowance_nonexistent_is_zero() {
    let mut s = Storage::new();
    let alice = addr("alice");
    let bob = addr("bob");

    let r = run(CODE, &mut s, &sel_addr_addr(0x05, &alice, &bob), &alice, 0, TS);
    assert_eq!(r.exit_code, 0);
    assert_eq!(output_u64(&r), 0);
}
