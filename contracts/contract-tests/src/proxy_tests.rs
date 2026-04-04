//! Tests for the proxy contract.
//!
//! Function selectors (1-byte):
//!   0xF0 — Init (21 bytes: selector + 20-byte impl address)
//!   0xF1 — Upgrade implementation (21 bytes)
//!   0xF2 — Propose new admin (21 bytes)
//!   0xF3 — Accept admin transfer (1 byte)
//!   0xF4 — Pause/unpause (2 bytes: selector + flag)
//!   default — Delegate call to implementation

use crate::harness::*;

const CODE: &[u8] = PROXY_CODE;

// ── Init ───────────────────────────────────────────────────────────────────

#[test]
fn init_sets_impl_and_admin() {
    let mut s = Storage::new();
    let deployer = addr("deployer");
    let impl_addr = addr("impl_v1");

    let r = run(CODE, &mut s, &proxy_sel_addr(0xF0, &impl_addr), &deployer, 0, 1_000_000);
    assert_eq!(r.exit_code, 0, "init should succeed");
}

#[test]
fn init_twice_fails() {
    let mut s = Storage::new();
    let deployer = addr("deployer");
    let impl1 = addr("impl_v1");
    let impl2 = addr("impl_v2");

    let r = run(CODE, &mut s, &proxy_sel_addr(0xF0, &impl1), &deployer, 0, 1_000_000);
    assert_eq!(r.exit_code, 0);

    let r = run(CODE, &mut s, &proxy_sel_addr(0xF0, &impl2), &deployer, 0, 1_000_000);
    assert_eq!(r.exit_code, 1, "second init should fail with 'already initialized'");
}

// ── Upgrade ────────────────────────────────────────────────────────────────

#[test]
fn upgrade_by_admin_succeeds() {
    let mut s = Storage::new();
    let admin = addr("admin");
    let impl1 = addr("impl_v1");
    let impl2 = addr("impl_v2");

    // Init
    run(CODE, &mut s, &proxy_sel_addr(0xF0, &impl1), &admin, 0, 1_000_000);

    // Upgrade
    let r = run(CODE, &mut s, &proxy_sel_addr(0xF1, &impl2), &admin, 0, 1_000_000);
    assert_eq!(r.exit_code, 0, "upgrade by admin should succeed");
}

#[test]
fn upgrade_by_non_admin_fails() {
    let mut s = Storage::new();
    let admin = addr("admin");
    let attacker = addr("attacker");
    let impl1 = addr("impl_v1");
    let impl2 = addr("impl_v2");

    run(CODE, &mut s, &proxy_sel_addr(0xF0, &impl1), &admin, 0, 1_000_000);

    let r = run(CODE, &mut s, &proxy_sel_addr(0xF1, &impl2), &attacker, 0, 1_000_000);
    assert_eq!(r.exit_code, 4, "non-admin upgrade should fail with 'unauthorized'");
}

#[test]
fn upgrade_before_init_fails() {
    let mut s = Storage::new();
    let anyone = addr("anyone");
    let impl1 = addr("impl_v1");

    let r = run(CODE, &mut s, &proxy_sel_addr(0xF1, &impl1), &anyone, 0, 1_000_000);
    assert_eq!(r.exit_code, 2, "upgrade before init should fail with 'not initialized'");
}

// ── Two-step admin transfer ────────────────────────────────────────────────

#[test]
fn admin_transfer_two_step() {
    let mut s = Storage::new();
    let admin = addr("admin");
    let new_admin = addr("new_admin");
    let impl1 = addr("impl_v1");

    // Init
    run(CODE, &mut s, &proxy_sel_addr(0xF0, &impl1), &admin, 0, 1_000_000);

    // Propose new admin
    let r = run(CODE, &mut s, &proxy_sel_addr(0xF2, &new_admin), &admin, 0, 1_000_000);
    assert_eq!(r.exit_code, 0, "propose should succeed");

    // Accept by new admin
    let r = run(CODE, &mut s, &proxy_sel(0xF3), &new_admin, 0, 1_000_000);
    assert_eq!(r.exit_code, 0, "accept should succeed");

    // Old admin can no longer upgrade
    let impl2 = addr("impl_v2");
    let r = run(CODE, &mut s, &proxy_sel_addr(0xF1, &impl2), &admin, 0, 1_000_000);
    assert_eq!(r.exit_code, 4, "old admin should be unauthorized");

    // New admin can upgrade
    let r = run(CODE, &mut s, &proxy_sel_addr(0xF1, &impl2), &new_admin, 0, 1_000_000);
    assert_eq!(r.exit_code, 0, "new admin should succeed");
}

#[test]
fn accept_admin_by_wrong_caller_fails() {
    let mut s = Storage::new();
    let admin = addr("admin");
    let proposed = addr("proposed");
    let attacker = addr("attacker");
    let impl1 = addr("impl_v1");

    run(CODE, &mut s, &proxy_sel_addr(0xF0, &impl1), &admin, 0, 1_000_000);
    run(CODE, &mut s, &proxy_sel_addr(0xF2, &proposed), &admin, 0, 1_000_000);

    let r = run(CODE, &mut s, &proxy_sel(0xF3), &attacker, 0, 1_000_000);
    assert_eq!(r.exit_code, 4, "wrong caller should fail with 'unauthorized'");
}

#[test]
fn accept_admin_with_no_pending_fails() {
    let mut s = Storage::new();
    let admin = addr("admin");
    let impl1 = addr("impl_v1");

    run(CODE, &mut s, &proxy_sel_addr(0xF0, &impl1), &admin, 0, 1_000_000);

    let r = run(CODE, &mut s, &proxy_sel(0xF3), &admin, 0, 1_000_000);
    assert_eq!(r.exit_code, 6, "no pending admin should fail");
}

#[test]
fn propose_admin_by_non_admin_fails() {
    let mut s = Storage::new();
    let admin = addr("admin");
    let attacker = addr("attacker");
    let proposed = addr("proposed");
    let impl1 = addr("impl_v1");

    run(CODE, &mut s, &proxy_sel_addr(0xF0, &impl1), &admin, 0, 1_000_000);

    let r = run(CODE, &mut s, &proxy_sel_addr(0xF2, &proposed), &attacker, 0, 1_000_000);
    assert_eq!(r.exit_code, 4, "non-admin propose should fail");
}

// ── Pause/Unpause ──────────────────────────────────────────────────────────

#[test]
fn pause_and_unpause() {
    let mut s = Storage::new();
    let admin = addr("admin");
    let impl1 = addr("impl_v1");

    run(CODE, &mut s, &proxy_sel_addr(0xF0, &impl1), &admin, 0, 1_000_000);

    // Pause
    let r = run(CODE, &mut s, &proxy_sel_flag(0xF4, 0x01), &admin, 0, 1_000_000);
    assert_eq!(r.exit_code, 0, "pause should succeed");

    // Fallback call while paused should fail
    let r = run(CODE, &mut s, b"\x00\x01\x02\x03", &admin, 0, 1_000_000);
    assert_eq!(r.exit_code, 7, "call while paused should fail");

    // Unpause
    let r = run(CODE, &mut s, &proxy_sel_flag(0xF4, 0x00), &admin, 0, 1_000_000);
    assert_eq!(r.exit_code, 0, "unpause should succeed");
}

#[test]
fn pause_by_non_admin_fails() {
    let mut s = Storage::new();
    let admin = addr("admin");
    let attacker = addr("attacker");
    let impl1 = addr("impl_v1");

    run(CODE, &mut s, &proxy_sel_addr(0xF0, &impl1), &admin, 0, 1_000_000);

    let r = run(CODE, &mut s, &proxy_sel_flag(0xF4, 0x01), &attacker, 0, 1_000_000);
    assert_eq!(r.exit_code, 4, "non-admin pause should fail");
}

// ── Edge cases ─────────────────────────────────────────────────────────────

#[test]
fn empty_calldata_fails() {
    let mut s = Storage::new();
    let anyone = addr("anyone");

    let r = run(CODE, &mut s, &[], &anyone, 0, 1_000_000);
    assert_eq!(r.exit_code, 5, "empty calldata should fail");
}
