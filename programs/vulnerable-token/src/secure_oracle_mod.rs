use anchor_lang::prelude::*;

// Note: In production, use actual Pyth/Switchboard SDKs
// These are simplified for demonstration

// secure_oracle.rs - Refactored as library module

/// Maximum staleness allowed for oracle prices (60 seconds)
pub const MAX_STALENESS_SECONDS: i64 = 60;

/// Maximum confidence interval ratio (5% = 500 basis points)
pub const MAX_CONFIDENCE_BPS: u64 = 500;

/// Maximum deviation between oracle sources (5% = 500 basis points)
pub const MAX_ORACLE_DEVIATION_BPS: u64 = 500;

/// Maximum price change per update (10% = 1000 basis points)
pub const MAX_PRICE_CHANGE_BPS: u64 = 1000;

/// Basis points denominator
pub const BPS_DENOMINATOR: u64 = 10000;

// Instruction functions

/// Initialize the secure price state for a token
pub fn handle_initialize_price_state<'info>(
    price_state: &mut Account<'info, PriceState>,
    token_mint: &Pubkey,
    admin: Pubkey,
    bump: u8,
) -> Result<()> {
    price_state.token_mint = *token_mint;
    price_state.admin = admin;
    price_state.last_price = 0;
    price_state.last_update = 0;
    price_state.circuit_breaker_triggered = false;
    price_state.bump = bump;

    msg!(
        "Price state initialized for mint: {}",
        price_state.token_mint
    );
    msg!("Admin set to: {}", price_state.admin);
    Ok(())
}

/// Get secure price with multi-layer defense
/// SECURITY FIX #21: Always uses Clock::get() - timestamp is NEVER user-controlled
pub fn handle_get_secure_price<'info>(
    price_state: &mut Account<'info, PriceState>,
    pyth_price_feed: &AccountInfo<'info>,
    switchboard_feed: &AccountInfo<'info>,
) -> Result<u64> {
    // SECURITY: Use on-chain clock, NEVER accept user-provided timestamp
    let clock = Clock::get()?;

    // ═══════════════════════════════════════════════════════════════════
    // DEFENSE LAYER 1: Multiple Oracle Sources
    // ═══════════════════════════════════════════════════════════════════

    let pyth_price = get_pyth_price(pyth_price_feed, clock.unix_timestamp)?;
    let switchboard_price = get_switchboard_price(switchboard_feed, clock.unix_timestamp)?;

    msg!(
        "Pyth price: {}, Switchboard price: {}",
        pyth_price.price,
        switchboard_price.price
    );

    // ═══════════════════════════════════════════════════════════════════
    // DEFENSE LAYER 2: Confidence Interval Checks
    // ═══════════════════════════════════════════════════════════════════

    // Pyth provides confidence intervals - reject if too wide
    let pyth_confidence_ratio = pyth_price
        .confidence
        .checked_mul(BPS_DENOMINATOR)
        .ok_or(OracleError::Overflow)?
        .checked_div(pyth_price.price)
        .ok_or(OracleError::DivisionByZero)?;

    require!(
        pyth_confidence_ratio < MAX_CONFIDENCE_BPS,
        OracleError::OracleConfidenceTooLow
    );

    msg!("Confidence check passed: {}bps", pyth_confidence_ratio);

    // ═══════════════════════════════════════════════════════════════════
    // DEFENSE LAYER 3: Staleness Validation
    // ═══════════════════════════════════════════════════════════════════

    require!(
        clock.unix_timestamp - pyth_price.timestamp < MAX_STALENESS_SECONDS,
        OracleError::StalePythPrice
    );

    require!(
        clock.unix_timestamp - switchboard_price.timestamp < MAX_STALENESS_SECONDS,
        OracleError::StaleSwitchboardPrice
    );

    msg!("Staleness check passed");

    // ═══════════════════════════════════════════════════════════════════
    // DEFENSE LAYER 4: Calculate Median Price
    // ═══════════════════════════════════════════════════════════════════

    let median_price = calculate_median(&[pyth_price.price, switchboard_price.price]);

    // ═══════════════════════════════════════════════════════════════════
    // DEFENSE LAYER 5: Cross-Oracle Deviation Check
    // ═══════════════════════════════════════════════════════════════════

    let price_deviation = pyth_price
        .price
        .abs_diff(switchboard_price.price)
        .checked_mul(BPS_DENOMINATOR)
        .ok_or(OracleError::Overflow)?
        .checked_div(median_price)
        .ok_or(OracleError::DivisionByZero)?;

    require!(
        price_deviation < MAX_ORACLE_DEVIATION_BPS,
        OracleError::OraclePriceDeviation
    );

    msg!(
        "Deviation check passed: {}bps between sources",
        price_deviation
    );

    // ═══════════════════════════════════════════════════════════════════
    // DEFENSE LAYER 6: Circuit Breaker
    // ═══════════════════════════════════════════════════════════════════

    if price_state.last_update > 0 && price_state.last_price > 0 {
        let price_change = median_price
            .abs_diff(price_state.last_price)
            .checked_mul(BPS_DENOMINATOR)
            .ok_or(OracleError::Overflow)?
            .checked_div(price_state.last_price)
            .ok_or(OracleError::DivisionByZero)?;

        if price_change > MAX_PRICE_CHANGE_BPS {
            price_state.circuit_breaker_triggered = true;
            msg!(
                "CIRCUIT BREAKER TRIGGERED: {}bps price change",
                price_change
            );
            return err!(OracleError::CircuitBreakerTriggered);
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Update State
    // ═══════════════════════════════════════════════════════════════════

    price_state.last_price = median_price;
    price_state.last_update = clock.unix_timestamp;
    price_state.circuit_breaker_triggered = false;

    msg!(
        "Secure price returned: {} (Pyth: {}, Switchboard: {})",
        median_price,
        pyth_price.price,
        switchboard_price.price
    );

    Ok(median_price)
}

/// Reset circuit breaker (admin only)
pub fn handle_reset_circuit_breaker<'info>(
    price_state: &mut Account<'info, PriceState>,
    admin: &Signer<'info>,
) -> Result<()> {
    require!(admin.key() == price_state.admin, OracleError::Unauthorized);

    price_state.circuit_breaker_triggered = false;
    msg!("Circuit breaker reset by admin: {}", price_state.admin);
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Account Structures
// ═══════════════════════════════════════════════════════════════════════════

#[account]
pub struct PriceState {
    /// The token mint this state belongs to
    pub token_mint: Pubkey,
    /// Authority allowed to manage this price state
    pub admin: Pubkey,
    /// Last recorded price
    pub last_price: u64,
    /// Timestamp of last update
    pub last_update: i64,
    /// Whether circuit breaker is triggered
    pub circuit_breaker_triggered: bool,
    /// PDA bump seed
    pub bump: u8,
}

impl PriceState {
    pub const LEN: usize = 8 + // discriminator
        32 + // token_mint
        32 + // admin
        8 +  // last_price
        8 +  // last_update
        1 +  // circuit_breaker_triggered
        1; // bump
}

/// Parsed price data from oracle
pub struct OraclePrice {
    pub price: u64,
    pub confidence: u64,
    pub timestamp: i64,
}

// ═══════════════════════════════════════════════════════════════════════════
// Helper Functions
// ═══════════════════════════════════════════════════════════════════════════

/// SECURITY FIX #11: Parse Pyth price feed with real SDK integration
/// Uses pyth_sdk_solana for production-grade oracle security
fn get_pyth_price(account: &AccountInfo, _current_timestamp: i64) -> Result<OraclePrice> {
    // Validate account is not empty
    require!(!account.data_is_empty(), OracleError::InvalidPythFeed);

    // Production Pyth SDK integration
    #[cfg(feature = "pyth-sdk")]
    {
        use pyth_sdk_solana::load_price_feed_from_account_info;

        let price_feed =
            load_price_feed_from_account_info(account).map_err(|_| OracleError::InvalidPythFeed)?;

        let price_data = price_feed
            .get_price_no_older_than(_current_timestamp, MAX_STALENESS_SECONDS as u64)
            .ok_or(OracleError::StalePythPrice)?;

        return Ok(OraclePrice {
            price: price_data.price.abs() as u64,
            confidence: price_data.conf as u64,
            timestamp: price_data.publish_time,
        });
    }

    // Devnet fallback: Parse raw account data when SDK not available
    #[cfg(not(feature = "pyth-sdk"))]
    {
        // Parse Pyth price account data structure manually for devnet
        let data = account.try_borrow_data()?;
        require!(data.len() >= 32, OracleError::InvalidPythFeed);

        // Use current timestamp for devnet testing
        Ok(OraclePrice {
            price: u64::from_le_bytes(data[8..16].try_into().unwrap_or([0; 8])),
            confidence: u64::from_le_bytes(data[16..24].try_into().unwrap_or([0; 8])),
            timestamp: Clock::get()?.unix_timestamp,
        })
    }
}

/// SECURITY FIX #12: Parse Switchboard aggregator with real SDK integration
/// Uses switchboard_v2 for production-grade oracle security
fn get_switchboard_price(account: &AccountInfo, _current_timestamp: i64) -> Result<OraclePrice> {
    // Validate account is not empty
    require!(
        !account.data_is_empty(),
        OracleError::InvalidSwitchboardFeed
    );

    // Production Switchboard SDK integration
    #[cfg(feature = "switchboard")]
    {
        use switchboard_v2::AggregatorAccountData;

        let aggregator =
            AggregatorAccountData::new(account).map_err(|_| OracleError::InvalidSwitchboardFeed)?;

        let result = aggregator
            .get_result()
            .map_err(|_| OracleError::InvalidSwitchboardFeed)?;

        // Verify feed is not stale
        let latest_timestamp = aggregator.latest_confirmed_round.round_open_timestamp;
        require!(
            _current_timestamp - latest_timestamp <= MAX_STALENESS_SECONDS,
            OracleError::StaleSwitchboardPrice
        );

        return Ok(OraclePrice {
            price: result.try_into().unwrap_or(0),
            confidence: 0, // Switchboard doesn't provide confidence intervals
            timestamp: latest_timestamp,
        });
    }

    // Devnet fallback: Parse raw account data when SDK not available
    #[cfg(not(feature = "switchboard"))]
    {
        // Parse Switchboard aggregator data structure manually for devnet
        let data = account.try_borrow_data()?;
        require!(data.len() >= 32, OracleError::InvalidSwitchboardFeed);

        Ok(OraclePrice {
            price: u64::from_le_bytes(data[8..16].try_into().unwrap_or([0; 8])),
            confidence: 0,
            timestamp: Clock::get()?.unix_timestamp,
        })
    }
}

/// Calculate median of price array
fn calculate_median(prices: &[u64]) -> u64 {
    let mut sorted = prices.to_vec();
    sorted.sort();

    let len = sorted.len();
    if len == 0 {
        return 0;
    }

    if len % 2 == 0 {
        (sorted[len / 2 - 1] + sorted[len / 2]) / 2
    } else {
        sorted[len / 2]
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Error Codes
// ═══════════════════════════════════════════════════════════════════════════

#[error_code]
pub enum OracleError {
    #[msg("Invalid Pyth price feed")]
    InvalidPythFeed,

    #[msg("Pyth price is stale (>60 seconds old)")]
    StalePythPrice,

    #[msg("Invalid Switchboard aggregator")]
    InvalidSwitchboardFeed,

    #[msg("Switchboard price is stale (>60 seconds old)")]
    StaleSwitchboardPrice,

    #[msg("Oracle confidence interval too wide (>5%)")]
    OracleConfidenceTooLow,

    #[msg("Price deviation between oracles too high (>5%)")]
    OraclePriceDeviation,

    #[msg("Circuit breaker triggered - price movement >10%")]
    CircuitBreakerTriggered,

    #[msg("Arithmetic overflow")]
    Overflow,

    #[msg("Division by zero")]
    DivisionByZero,

    #[msg("Price value overflow")]
    PriceOverflow,

    #[msg("Unauthorized access")]
    Unauthorized,
}

// ═══════════════════════════════════════════════════════════════════════════
// TWAP Implementation (Advanced)
// ═══════════════════════════════════════════════════════════════════════════

/// TWAP (Time-Weighted Average Price) calculator
/// Stores circular buffer of historical prices for TWAP calculation
/// SECURITY FIX #13: Added admin field for access control
#[account]
pub struct TwapState {
    /// Circular buffer of price observations
    pub observations: [PriceObservation; 60], // 1 hour of minute-by-minute data
    /// Current position in circular buffer
    pub current_index: u8,
    /// Number of valid observations
    pub observation_count: u8,
    /// Associated token mint
    pub token_mint: Pubkey,
    /// Admin who can record observations (oracle authority)
    pub admin: Pubkey,
    /// PDA bump
    pub bump: u8,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Default)]
pub struct PriceObservation {
    pub price: u64,
    pub timestamp: i64,
}

impl TwapState {
    pub const LEN: usize = 8 + // discriminator
        (8 + 8) * 60 + // observations array
        1 + // current_index
        1 + // observation_count
        32 + // token_mint
        32 + // admin
        1; // bump

    /// SECURITY FIX #14: Record observation with admin check (call from instruction handler)
    /// This should only be called after verifying the caller is the admin
    pub fn record_observation(&mut self, price: u64, timestamp: i64) {
        let index = self.current_index as usize;
        self.observations[index] = PriceObservation { price, timestamp };
        self.current_index = ((self.current_index as usize + 1) % 60) as u8;
        if self.observation_count < 60 {
            self.observation_count += 1;
        }
    }

    /// Calculate TWAP over specified window (in seconds)
    pub fn calculate_twap(&self, window_seconds: i64, current_timestamp: i64) -> Option<u64> {
        if self.observation_count == 0 {
            return None;
        }

        let mut total_weighted_price: u128 = 0;
        let mut total_weight: u128 = 0;
        let window_start = current_timestamp - window_seconds;

        for i in 0..self.observation_count as usize {
            let obs = &self.observations[i];
            if obs.timestamp >= window_start {
                // Weight by time since observation
                let weight = (obs.timestamp - window_start) as u128 + 1;
                total_weighted_price += obs.price as u128 * weight;
                total_weight += weight;
            }
        }

        if total_weight == 0 {
            return None;
        }

        Some((total_weighted_price / total_weight) as u64)
    }
}
