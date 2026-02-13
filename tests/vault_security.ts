// =============================================================================
// Vault Security Integration Tests
// =============================================================================
//
// This test suite demonstrates the CONTRAST between the vulnerable-vault and
// security_shield programs. It tests:
//
//   1. The vulnerable vault allows the first-depositor attack
//   2. The security shield prevents it via MIN_FIRST_DEPOSIT guard
//   3. The security shield properly transfers tokens on withdraw
//   4. Emergency pause access control (vuln vs secure)
//
// Run with: anchor test
//
// =============================================================================

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SecurityShield } from "../target/types/security_shield";
import { VulnerableVault } from "../target/types/vulnerable_vault";
import { expect } from "chai";
import { Keypair, LAMPORTS_PER_SOL, PublicKey } from "@solana/web3.js";
import { TOKEN_PROGRAM_ID, createMint, createAccount, mintTo, getAccount } from "@solana/spl-token";

describe("vault-security: Vulnerable vs Secure Comparison", () => {
    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);

    const secureProgram = anchor.workspace.SecurityShield as Program<SecurityShield>;
    const vulnProgram = anchor.workspace.VulnerableVault as Program<VulnerableVault>;

    let mint: PublicKey;
    let attacker = Keypair.generate();
    let victim = Keypair.generate();

    // ─── Secure vault PDAs & token accounts ─────────────────────────
    const [secureVaultPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("vault")],
        secureProgram.programId
    );
    let secureVaultToken: PublicKey;
    let secureAttackerToken: PublicKey;
    let secureVictimToken: PublicKey;

    // ─── Vulnerable vault PDAs & token accounts ─────────────────────
    const [vulnVaultPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("vault")],
        vulnProgram.programId
    );
    let vulnVaultToken: PublicKey;
    let vulnAttackerToken: PublicKey;
    let vulnVictimToken: PublicKey;

    before(async () => {
        // Airdrop SOL
        for (const kp of [attacker, victim]) {
            const sig = await provider.connection.requestAirdrop(kp.publicKey, 10 * LAMPORTS_PER_SOL);
            const latestBlockhash = await provider.connection.getLatestBlockhash();
            await provider.connection.confirmTransaction({ signature: sig, ...latestBlockhash });
        }

        // Create shared mint
        mint = await createMint(
            provider.connection,
            (provider.wallet as any).payer,
            provider.wallet.publicKey,
            null,
            9
        );

        // Create token accounts for secure program
        secureVaultToken = await createAccount(
            provider.connection,
            (provider.wallet as any).payer,
            mint,
            secureVaultPda,
            undefined,
            { skipPreflight: true }
        );
        secureAttackerToken = await createAccount(
            provider.connection,
            (provider.wallet as any).payer,
            mint,
            attacker.publicKey
        );
        secureVictimToken = await createAccount(
            provider.connection,
            (provider.wallet as any).payer,
            mint,
            victim.publicKey
        );

        // Create token accounts for vulnerable program
        vulnVaultToken = await createAccount(
            provider.connection,
            (provider.wallet as any).payer,
            mint,
            vulnVaultPda,
            Keypair.generate(), // use different keypair to avoid collision
            { skipPreflight: true }
        );
        vulnAttackerToken = await createAccount(
            provider.connection,
            (provider.wallet as any).payer,
            mint,
            attacker.publicKey,
            Keypair.generate()
        );
        vulnVictimToken = await createAccount(
            provider.connection,
            (provider.wallet as any).payer,
            mint,
            victim.publicKey,
            Keypair.generate()
        );

        // Mint tokens to attacker and victim for both programs
        const mintAmount = 5_000_000_000; // 5 SOL worth
        await mintTo(provider.connection, (provider.wallet as any).payer, mint, secureAttackerToken, provider.wallet.publicKey, mintAmount);
        await mintTo(provider.connection, (provider.wallet as any).payer, mint, secureVictimToken, provider.wallet.publicKey, mintAmount);
        await mintTo(provider.connection, (provider.wallet as any).payer, mint, vulnAttackerToken, provider.wallet.publicKey, mintAmount);
        await mintTo(provider.connection, (provider.wallet as any).payer, mint, vulnVictimToken, provider.wallet.publicKey, mintAmount);
    });

    // ═══════════════════════════════════════════════════════════════════
    //  SECTION 1: First-Depositor Attack
    // ═══════════════════════════════════════════════════════════════════

    describe("1. First-Depositor Attack", () => {
        it("SECURE: Rejects 1-lamport first deposit (MIN_FIRST_DEPOSIT guard)", async () => {
            // Initialize secure vault
            await secureProgram.methods
                .initializeVault()
                .accounts({
                    vault: secureVaultPda,
                    admin: attacker.publicKey,
                    mint: mint,
                    systemProgram: anchor.web3.SystemProgram.programId,
                })
                .signers([attacker])
                .rpc();

            const [attackerSharesPda] = PublicKey.findProgramAddressSync(
                [Buffer.from("user_shares"), attacker.publicKey.toBuffer()],
                secureProgram.programId
            );

            await secureProgram.methods
                .initializeUserShares()
                .accounts({
                    userShares: attackerSharesPda,
                    user: attacker.publicKey,
                    systemProgram: anchor.web3.SystemProgram.programId,
                })
                .signers([attacker])
                .rpc();

            // 1-lamport deposit should be rejected
            let failed = false;
            try {
                await secureProgram.methods
                    .deposit(new anchor.BN(1))
                    .accounts({
                        vault: secureVaultPda,
                        userShares: attackerSharesPda,
                        userToken: secureAttackerToken,
                        vaultToken: secureVaultToken,
                        user: attacker.publicKey,
                        tokenProgram: TOKEN_PROGRAM_ID,
                    })
                    .signers([attacker])
                    .rpc();
            } catch (err) {
                failed = true;
                console.log("  ✅ Secure vault rejected 1-lamport deposit:", (err as Error).message.substring(0, 80));
            }

            expect(failed).to.equal(true, "Secure vault must reject tiny first deposits");
        });

        it("VULNERABLE: Accepts 1-lamport first deposit (no guard!)", async () => {
            // Initialize vulnerable vault
            await vulnProgram.methods
                .initializeVault()
                .accounts({
                    vault: vulnVaultPda,
                    admin: attacker.publicKey,
                    mint: mint,
                    systemProgram: anchor.web3.SystemProgram.programId,
                })
                .signers([attacker])
                .rpc();

            const [attackerSharesPda] = PublicKey.findProgramAddressSync(
                [Buffer.from("user_shares"), attacker.publicKey.toBuffer()],
                vulnProgram.programId
            );

            await vulnProgram.methods
                .initializeUserShares()
                .accounts({
                    userShares: attackerSharesPda,
                    user: attacker.publicKey,
                    systemProgram: anchor.web3.SystemProgram.programId,
                })
                .signers([attacker])
                .rpc();

            // 1-lamport deposit should succeed on vulnerable program
            await vulnProgram.methods
                .deposit(new anchor.BN(1))
                .accounts({
                    vault: vulnVaultPda,
                    userShares: attackerSharesPda,
                    userToken: vulnAttackerToken,
                    vaultToken: vulnVaultToken,
                    user: attacker.publicKey,
                    tokenProgram: TOKEN_PROGRAM_ID,
                })
                .signers([attacker])
                .rpc();

            const shares = await vulnProgram.account.userShares.fetch(attackerSharesPda);
            expect(shares.shares.toNumber()).to.equal(1);
            console.log("  ⚠️  Vulnerable vault accepted 1-lamport deposit — attack possible!");
        });
    });

    // ═══════════════════════════════════════════════════════════════════
    //  SECTION 2: Emergency Pause Access Control
    // ═══════════════════════════════════════════════════════════════════

    describe("2. Emergency Pause Access Control", () => {
        const [secureEmergencyPda] = PublicKey.findProgramAddressSync(
            [Buffer.from("emergency_state")],
            secureProgram.programId
        );
        const [vulnEmergencyPda] = PublicKey.findProgramAddressSync(
            [Buffer.from("emergency_state")],
            vulnProgram.programId
        );

        it("Setup: Initialize emergency state on both programs", async () => {
            await secureProgram.methods
                .initializeEmergencyState()
                .accounts({
                    emergencyState: secureEmergencyPda,
                    admin: attacker.publicKey, // attacker is admin for this test
                    systemProgram: anchor.web3.SystemProgram.programId,
                })
                .signers([attacker])
                .rpc();

            await vulnProgram.methods
                .initializeEmergencyState()
                .accounts({
                    emergencyState: vulnEmergencyPda,
                    admin: attacker.publicKey,
                    systemProgram: anchor.web3.SystemProgram.programId,
                })
                .signers([attacker])
                .rpc();
        });

        it("SECURE: Rejects non-admin emergency pause", async () => {
            let failed = false;
            try {
                await secureProgram.methods
                    .emergencyPause("hacked!", new anchor.BN(3600))
                    .accounts({
                        emergencyState: secureEmergencyPda,
                        caller: victim.publicKey, // victim is NOT admin
                    })
                    .signers([victim])
                    .rpc();
            } catch (err) {
                failed = true;
                console.log("  ✅ Secure program rejected non-admin pause");
            }
            expect(failed).to.equal(true, "Non-admin must be rejected");
        });

        it("VULNERABLE: Allows anyone to pause the protocol!", async () => {
            await vulnProgram.methods
                .emergencyPause("griefing attack", new anchor.BN(3600))
                .accounts({
                    emergencyState: vulnEmergencyPda,
                    caller: victim.publicKey, // victim pauses — NOT admin!
                })
                .signers([victim])
                .rpc();

            const state = await vulnProgram.account.emergencyState.fetch(vulnEmergencyPda);
            expect(state.isPaused).to.equal(true);
            console.log("  ⚠️  Vulnerable program allowed non-admin to pause protocol!");
        });
    });

    // ═══════════════════════════════════════════════════════════════════
    //  SECTION 3: Withdraw Token Transfer
    // ═══════════════════════════════════════════════════════════════════

    describe("3. Withdraw Token Transfer", () => {
        it("SECURE: Withdraw actually transfers tokens back to user", async () => {
            const [attackerSharesPda] = PublicKey.findProgramAddressSync(
                [Buffer.from("user_shares"), attacker.publicKey.toBuffer()],
                secureProgram.programId
            );

            // First do a valid deposit on secure program
            const depositAmount = new anchor.BN(1_000_000); // MIN_FIRST_DEPOSIT
            await secureProgram.methods
                .deposit(depositAmount)
                .accounts({
                    vault: secureVaultPda,
                    userShares: attackerSharesPda,
                    userToken: secureAttackerToken,
                    vaultToken: secureVaultToken,
                    user: attacker.publicKey,
                    tokenProgram: TOKEN_PROGRAM_ID,
                })
                .signers([attacker])
                .rpc();

            const balanceBefore = (await getAccount(provider.connection, secureAttackerToken)).amount;

            // Withdraw shares — should return tokens
            const shares = await secureProgram.account.userShares.fetch(attackerSharesPda);
            await secureProgram.methods
                .withdraw(new anchor.BN(shares.shares.toNumber()))
                .accounts({
                    vault: secureVaultPda,
                    userShares: attackerSharesPda,
                    userToken: secureAttackerToken,
                    vaultToken: secureVaultToken,
                    user: attacker.publicKey,
                    tokenProgram: TOKEN_PROGRAM_ID,
                })
                .signers([attacker])
                .rpc();

            const balanceAfter = (await getAccount(provider.connection, secureAttackerToken)).amount;
            expect(Number(balanceAfter)).to.be.greaterThan(Number(balanceBefore));
            console.log(`  ✅ Secure withdraw returned ${Number(balanceAfter) - Number(balanceBefore)} tokens`);
        });
    });

    after(() => {
        console.log("");
        console.log("═".repeat(60));
        console.log("Vault Security: Vulnerable vs Secure Comparison Complete");
        console.log("═".repeat(60));
    });
});
