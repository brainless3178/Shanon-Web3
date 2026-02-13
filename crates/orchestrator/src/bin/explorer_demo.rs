use anyhow::Result;
use orchestrator::chain_explorer::ChainExplorer;

#[tokio::main]
async fn main() -> Result<()> {
    let explorer = ChainExplorer::new("https://api.mainnet-beta.solana.com".to_string());

    println!("--- SOLANA NETWORK VITALS ---");
    let stats = explorer.fetch_network_stats()?;
    println!("TPS: {:.2}", stats.tps);
    println!("Slot: {}", stats.slot);
    println!("Block Height: {}", stats.block_height);

    println!("\n--- ACCOUNT RECONNAISSANCE ---");
    // Serum Program: 9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin
    match explorer.inspect_account("9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin") {
        Ok(acc) => {
            println!("Address: {}", acc.pubkey);
            println!("Balance: {:.4} SOL", acc.sol_balance);
            println!("Owner:   {}", acc.owner);
            println!("Data:    {} bytes", acc.data_len);
            println!("Exec:    {}", acc.executable);
        }
        Err(e) => println!("Error fetching account: {}", e),
    }

    println!("\n--- TRANSACTION FORENSICS ---");
    // A random recent signature would be better, but let's try a known one or just skip if none.
    // I'll try to find a recent signature from the network stats if possible,
    // but explorer doesn't have list_recent_sigs yet.
    // Let's use a hardcoded famous one: the first tx of the network or something.
    // Actually, I'll just check if the account fetch worked.

    Ok(())
}
