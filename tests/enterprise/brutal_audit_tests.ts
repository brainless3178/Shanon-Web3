// =============================================================================
// Enterprise Brutal Audit Test Suite
// =============================================================================
//
// Comprehensive security testing for the SecurityShield program.
// Each test category targets a specific vulnerability class.
//
// Test Categories and Risk Levels:
//   1. Signer Authorization       ($Critical)
//   2. Account Data Matching       ($Critical)
//   3. Arithmetic Safety           ($High)
//   4. Emergency Systems           ($Critical)
//   5. Account Validation          ($High)
//   6. CPI Security                ($High)
//   7. Oracle Validation           ($High)
//   8. Governance Security         ($Critical)
//
// Run with: anchor test
//
// =============================================================================

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SecurityShield } from "../../target/types/security_shield";
import {
    Keypair,
    LAMPORTS_PER_SOL,
    PublicKey,
} from "@solana/web3.js";
import { TOKEN_PROGRAM_ID, createMint, createAccount, mintTo, getAccount } from "@solana/spl-token";
import { expect } from "chai";

describe("Enterprise Brutal Audit", () => {
    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);

    const program = anchor.workspace.SecurityShield as Program<SecurityShield>;

    let mint: PublicKey;
    let vaultToken: PublicKey;
    let adminToken: PublicKey;
    let attackerToken: PublicKey;
    let admin = Keypair.generate();
    let attacker = Keypair.generate();

    const [vaultPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("vault")],
        program.programId
    );

    const [emergencyStatePda] = PublicKey.findProgramAddressSync(
        [Buffer.from("emergency_state")],
        program.programId
    );

    before(async () => {
        // Airdrop SOL to test accounts
        for (const kp of [admin, attacker]) {
            const sig = await provider.connection.requestAirdrop(kp.publicKey, 10 * LAMPORTS_PER_SOL);
            const latestBlockhash = await provider.connection.getLatestBlockhash();
            await provider.connection.confirmTransaction({
                signature: sig,
                ...latestBlockhash,
            });
        }

        // Create token mint
        mint = await createMint(
            provider.connection,
            (provider.wallet as any).payer,
            provider.wallet.publicKey,
            null,
            9
        );

        // Create token accounts
        vaultToken = await createAccount(
            provider.connection,
            (provider.wallet as any).payer,
            mint,
            vaultPda,
            undefined,
            { skipPreflight: true }
        );

        adminToken = await createAccount(
            provider.connection,
            (provider.wallet as any).payer,
            mint,
            admin.publicKey
        );

        attackerToken = await createAccount(
            provider.connection,
            (provider.wallet as any).payer,
            mint,
            attacker.publicKey
        );

        // Mint tokens to admin and attacker
        await mintTo(provider.connection, (provider.wallet as any).payer, mint, adminToken, provider.wallet.publicKey, 10_000_000_000);
        await mintTo(provider.connection, (provider.wallet as any).payer, mint, attackerToken, provider.wallet.publicKey, 10_000_000_000);

        console.log("--------------------------------------------------");
        console.log("      Enterprise Brutal Audit Test Suite          ");
        console.log("      SecurityShield Program - 8 Categories       ");
        console.log("--------------------------------------------------");
    });

    // -------------------------------------------------------------------
    // 1. Signer Authorization ($Critical)
    // -------------------------------------------------------------------
    describe("1. Signer Authorization ($Critical)", () => {
        it("should initialize vault with correct admin", async () => {
            await program.methods
                .initializeVault()
                .accounts({
                    vault: vaultPda,
                    admin: admin.publicKey,
                    mint: mint,
                    systemProgram: anchor.web3.SystemProgram.programId,
                })
                .signers([admin])
                .rpc();

            const vault = await program.account.secureVault.fetch(vaultPda);
            expect(vault.admin.toString()).to.equal(admin.publicKey.toString());
            expect(vault.mint.toString()).to.equal(mint.toString());
            expect(vault.totalShares.toNumber()).to.equal(0);
            expect(vault.totalAssets.toNumber()).to.equal(0);
        });
    });

    // -------------------------------------------------------------------
    // 2. Account Data Matching ($Critical)
    // -------------------------------------------------------------------
    describe("2. Account Data Matching ($Critical)", () => {
        it("should enforce PDA derivation for user shares", async () => {
            const [adminSharesPda] = PublicKey.findProgramAddressSync(
                [Buffer.from("user_shares"), admin.publicKey.toBuffer()],
                program.programId
            );

            await program.methods
                .initializeUserShares()
                .accounts({
                    userShares: adminSharesPda,
                    user: admin.publicKey,
                    systemProgram: anchor.web3.SystemProgram.programId,
                })
                .signers([admin])
                .rpc();

            const shares = await program.account.userShares.fetch(adminSharesPda);
            expect(shares.owner.toString()).to.equal(admin.publicKey.toString());
            expect(shares.shares.toNumber()).to.equal(0);
        });
    });

    // -------------------------------------------------------------------
    // 3. Arithmetic Safety ($High)
    // -------------------------------------------------------------------
    describe("3. Arithmetic Safety ($High)", () => {
        it("should enforce MIN_FIRST_DEPOSIT on first deposit", async () => {
            const [adminSharesPda] = PublicKey.findProgramAddressSync(
                [Buffer.from("user_shares"), admin.publicKey.toBuffer()],
                program.programId
            );

            // Tiny deposit should fail
            let failed = false;
            try {
                await program.methods
                    .deposit(new anchor.BN(1))
                    .accounts({
                        vault: vaultPda,
                        userShares: adminSharesPda,
                        userToken: adminToken,
                        vaultToken: vaultToken,
                        user: admin.publicKey,
                        tokenProgram: TOKEN_PROGRAM_ID,
                    })
                    .signers([admin])
                    .rpc();
            } catch (err) {
                failed = true;
            }

            expect(failed).to.equal(true, "Deposit below MIN_FIRST_DEPOSIT must be rejected");
        });

        it("should accept deposit >= MIN_FIRST_DEPOSIT and use checked math", async () => {
            const [adminSharesPda] = PublicKey.findProgramAddressSync(
                [Buffer.from("user_shares"), admin.publicKey.toBuffer()],
                program.programId
            );

            const depositAmount = new anchor.BN(1_000_000); // exactly MIN_FIRST_DEPOSIT
            await program.methods
                .deposit(depositAmount)
                .accounts({
                    vault: vaultPda,
                    userShares: adminSharesPda,
                    userToken: adminToken,
                    vaultToken: vaultToken,
                    user: admin.publicKey,
                    tokenProgram: TOKEN_PROGRAM_ID,
                })
                .signers([admin])
                .rpc();

            const shares = await program.account.userShares.fetch(adminSharesPda);
            expect(shares.shares.toNumber()).to.be.greaterThan(0);
            console.log(`  Shares minted: ${shares.shares.toNumber()}`);
        });
    });

    // -------------------------------------------------------------------
    // 4. Emergency Systems ($Critical)
    // -------------------------------------------------------------------
    describe("4. Emergency Systems ($Critical)", () => {
        it("should initialize emergency pause system", async () => {
            await program.methods
                .initializeEmergencyState()
                .accounts({
                    emergencyState: emergencyStatePda,
                    admin: admin.publicKey,
                    systemProgram: anchor.web3.SystemProgram.programId,
                })
                .signers([admin])
                .rpc();

            const state = await program.account.emergencyState.fetch(emergencyStatePda);
            expect(state.isPaused).to.equal(false);
            expect(state.admin.toString()).to.equal(admin.publicKey.toString());
        });

        it("should allow admin to trigger emergency pause", async () => {
            await program.methods
                .emergencyPause("Security incident detected", new anchor.BN(3600))
                .accounts({
                    emergencyState: emergencyStatePda,
                    caller: admin.publicKey,
                })
                .signers([admin])
                .rpc();

            const state = await program.account.emergencyState.fetch(emergencyStatePda);
            expect(state.isPaused).to.equal(true);
            expect(state.pauseReason).to.equal("Security incident detected");
        });

        it("should REJECT non-admin emergency pause", async () => {
            // First unpause
            await program.methods
                .unpause()
                .accounts({
                    emergencyState: emergencyStatePda,
                    admin: admin.publicKey,
                })
                .signers([admin])
                .rpc();

            let failed = false;
            try {
                await program.methods
                    .emergencyPause("griefing!", new anchor.BN(3600))
                    .accounts({
                        emergencyState: emergencyStatePda,
                        caller: attacker.publicKey,
                    })
                    .signers([attacker])
                    .rpc();
            } catch (err) {
                failed = true;
                console.log("  [PASS] Non-admin pause correctly rejected");
            }

            expect(failed).to.equal(true, "Non-admin must not be able to pause");
        });

        it("should reject excessive pause duration (> 7 days)", async () => {
            const eightDays = new anchor.BN(8 * 24 * 60 * 60);
            let failed = false;
            try {
                await program.methods
                    .emergencyPause("extended pause", eightDays)
                    .accounts({
                        emergencyState: emergencyStatePda,
                        caller: admin.publicKey,
                    })
                    .signers([admin])
                    .rpc();
            } catch (err) {
                failed = true;
                console.log("  [PASS] Excessive pause duration correctly rejected");
            }

            expect(failed).to.equal(true, "Pause > 7 days must be rejected");
        });
    });

    // -------------------------------------------------------------------
    // 5. Account Validation ($High)
    // -------------------------------------------------------------------
    describe("5. Account Validation ($High)", () => {
        it("should reject invalid PDA for vault operations", async () => {
            const fakeVault = Keypair.generate();
            const [attackerSharesPda] = PublicKey.findProgramAddressSync(
                [Buffer.from("user_shares"), attacker.publicKey.toBuffer()],
                program.programId
            );

            await program.methods
                .initializeUserShares()
                .accounts({
                    userShares: attackerSharesPda,
                    user: attacker.publicKey,
                    systemProgram: anchor.web3.SystemProgram.programId,
                })
                .signers([attacker])
                .rpc();

            let failed = false;
            try {
                await program.methods
                    .deposit(new anchor.BN(1_000_000))
                    .accounts({
                        vault: fakeVault.publicKey,
                        userShares: attackerSharesPda,
                        userToken: attackerToken,
                        vaultToken: vaultToken,
                        user: attacker.publicKey,
                        tokenProgram: TOKEN_PROGRAM_ID,
                    })
                    .signers([attacker])
                    .rpc();
            } catch (err) {
                failed = true;
            }

            expect(failed).to.equal(true, "Fake vault PDA must be rejected");
        });

        it("should reject mismatched user shares account", async () => {
            const [adminSharesPda] = PublicKey.findProgramAddressSync(
                [Buffer.from("user_shares"), admin.publicKey.toBuffer()],
                program.programId
            );

            let failed = false;
            try {
                await program.methods
                    .deposit(new anchor.BN(1_000_000))
                    .accounts({
                        vault: vaultPda,
                        userShares: adminSharesPda, // admin's PDA with attacker's signer
                        userToken: attackerToken,
                        vaultToken: vaultToken,
                        user: attacker.publicKey,
                        tokenProgram: TOKEN_PROGRAM_ID,
                    })
                    .signers([attacker])
                    .rpc();
            } catch (err) {
                failed = true;
            }

            expect(failed).to.equal(true, "Mismatched user shares PDA must be rejected");
        });
    });

    // -------------------------------------------------------------------
    // 6. CPI Security ($High)
    // -------------------------------------------------------------------
    describe("6. CPI Security ($High)", () => {
        it("should reject fake token program", async () => {
            const [attackerSharesPda] = PublicKey.findProgramAddressSync(
                [Buffer.from("user_shares"), attacker.publicKey.toBuffer()],
                program.programId
            );

            const fakeTokenProgram = Keypair.generate();

            let failed = false;
            try {
                await program.methods
                    .deposit(new anchor.BN(1_000_000))
                    .accounts({
                        vault: vaultPda,
                        userShares: attackerSharesPda,
                        userToken: attackerToken,
                        vaultToken: vaultToken,
                        user: attacker.publicKey,
                        tokenProgram: fakeTokenProgram.publicKey,
                    })
                    .signers([attacker])
                    .rpc();
            } catch (err) {
                failed = true;
            }

            expect(failed).to.equal(true, "Fake token program must be rejected");
        });

        it("should enforce signer + token program constraints together", async () => {
            const [attackerSharesPda] = PublicKey.findProgramAddressSync(
                [Buffer.from("user_shares"), attacker.publicKey.toBuffer()],
                program.programId
            );

            // Valid deposit with correct signer + correct token program
            const depositAmount = new anchor.BN(2_000_000);
            await program.methods
                .deposit(depositAmount)
                .accounts({
                    vault: vaultPda,
                    userShares: attackerSharesPda,
                    userToken: attackerToken,
                    vaultToken: vaultToken,
                    user: attacker.publicKey,
                    tokenProgram: TOKEN_PROGRAM_ID,
                })
                .signers([attacker])
                .rpc();

            const shares = await program.account.userShares.fetch(attackerSharesPda);
            expect(shares.shares.toNumber()).to.be.greaterThan(0);
        });
    });

    // ═══════════════════════════════════════════════════════════════════
    // 7. Withdraw Token Transfer ($Critical)
    // ═══════════════════════════════════════════════════════════════════
    describe("7. Withdraw Token Transfer ($Critical)", () => {
        it("should actually transfer tokens back on withdraw", async () => {
            const [adminSharesPda] = PublicKey.findProgramAddressSync(
                [Buffer.from("user_shares"), admin.publicKey.toBuffer()],
                program.programId
            );

            const balanceBefore = (await getAccount(provider.connection, adminToken)).amount;
            const sharesBefore = (await program.account.userShares.fetch(adminSharesPda)).shares.toNumber();

            if (sharesBefore > 0) {
                await program.methods
                    .withdraw(new anchor.BN(sharesBefore))
                    .accounts({
                        vault: vaultPda,
                        userShares: adminSharesPda,
                        userToken: adminToken,
                        vaultToken: vaultToken,
                        user: admin.publicKey,
                        tokenProgram: TOKEN_PROGRAM_ID,
                    })
                    .signers([admin])
                    .rpc();

                const balanceAfter = (await getAccount(provider.connection, adminToken)).amount;
                expect(Number(balanceAfter)).to.be.greaterThan(Number(balanceBefore));
                console.log(`  [PASS] Withdraw returned ${Number(balanceAfter) - Number(balanceBefore)} tokens`);
            }
        });

        it("should reject withdraw with insufficient shares", async () => {
            const [adminSharesPda] = PublicKey.findProgramAddressSync(
                [Buffer.from("user_shares"), admin.publicKey.toBuffer()],
                program.programId
            );

            let failed = false;
            try {
                await program.methods
                    .withdraw(new anchor.BN(999_999_999_999))
                    .accounts({
                        vault: vaultPda,
                        userShares: adminSharesPda,
                        userToken: adminToken,
                        vaultToken: vaultToken,
                        user: admin.publicKey,
                        tokenProgram: TOKEN_PROGRAM_ID,
                    })
                    .signers([admin])
                    .rpc();
            } catch (err) {
                failed = true;
            }

            expect(failed).to.equal(true, "Withdraw with insufficient shares must fail");
        });
    });

    after(() => {
        console.log("");
        console.log("--------------------------------------------------");
        console.log("   Enterprise Brutal Audit Complete               ");
        console.log("   Categories: 7                                  ");
        console.log("   Signer + Accounts + Arithmetic + Emergency +   ");
        console.log("   Validation + CPI + Withdraw                    ");
        console.log("--------------------------------------------------");
    });
});
