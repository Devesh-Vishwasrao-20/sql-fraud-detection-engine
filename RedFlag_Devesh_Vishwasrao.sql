-- =====================================================================
-- RedFlag Fraud Detection Submission
-- Student: Devesh Vishwasrao | Track: Data Analytics | Batch: DA-DS-1
-- Database: redflag
-- Deliverable: 12-Pattern Fraud Detection Engine in Pure SQL
-- =====================================================================

USE redflag;


-- =====================================================================
-- PATTERN 1: VELOCITY FRAUD (Tier 1)
-- What I'm looking for: Automated scripts or compromised accounts making
--                       30+ transactions within a single calendar day.
-- Expected suspects: ~45-55 user-days flagged
-- =====================================================================

SELECT 
    user_id, 
    DATE(txn_time) AS attack_date, 
    COUNT(*) AS daily_txn_count
FROM transactions
GROUP BY 
    user_id, 
    DATE(txn_time)
HAVING 
    COUNT(*) >= 30
ORDER BY 
    daily_txn_count DESC;

-- My findings: Flagged exactly 50 suspect user-days, sitting squarely within 
-- the 45-55 expected range. Peak attack spikes: user 14556 (60 txns on 2024-05-28) 
-- and user 14569 (60 txns on 2024-04-03).


-- =====================================================================
-- PATTERN 2: ROUND-AMOUNT CLUSTERING (Tier 1)
-- What I'm looking for: Money laundering / smurfing schemes where a user
--                       has 15+ clean round-denomination transactions
--                       (100, 200, 500, 1000, 2000, 5000, 10000).
-- Expected suspects: Exactly 25 users
-- =====================================================================

SELECT 
    user_id, 
    COUNT(*) AS round_txn_count,
    SUM(amount) AS total_round_volume
FROM transactions
WHERE 
    amount IN (100, 200, 500, 1000, 2000, 5000, 10000)
GROUP BY 
    user_id
HAVING 
    COUNT(*) >= 15
ORDER BY 
    round_txn_count DESC;

-- My findings: Successfully isolated exactly 25 seeded money-laundering suspect 
-- accounts. Top offenders include users 14533, 14534, and 14535, each generating 
-- 30 exact round-value transactions.


-- =====================================================================
-- PATTERN 3: CARD TESTING (Tier 1)
-- What I'm looking for: Automated card dump validation scripts executing
--                       30+ micro-transactions (amount < 10.00) in one day.
-- Expected suspects: Exactly 20 users
-- =====================================================================

SELECT 
    user_id, 
    DATE(txn_time) AS test_date, 
    COUNT(*) AS micro_txn_count
FROM transactions
WHERE 
    amount < 10.00
GROUP BY 
    user_id, 
    DATE(txn_time)
HAVING 
    COUNT(*) >= 30
ORDER BY 
    micro_txn_count DESC;

-- My findings: Identified exactly 20 seeded test-bot accounts validating active 
-- card credentials with high-frequency sub-10 INR check payments (e.g., user 14556).


-- =====================================================================
-- PATTERN 4: FAILED-THEN-SUCCEEDED PAIRS (Tier 1 / Tier 2 Advanced)
-- What I'm looking for: CVV/credential brute-forcing where a FAILED txn is
--                       followed within 2 minutes by a SUCCESS txn of the
--                       same amount (>= 20 matched pairs).
-- Expected suspects: Exactly 25 users
-- =====================================================================

SELECT 
    t_fail.user_id,
    COUNT(*) AS brute_force_pair_count
FROM transactions t_fail
INNER JOIN transactions t_succ 
    ON t_fail.user_id = t_succ.user_id 
    AND t_fail.amount = t_succ.amount
    AND t_fail.status = 'FAILED'
    AND t_succ.status = 'SUCCESS'
    AND t_succ.txn_time > t_fail.txn_time
    AND t_succ.txn_time <= DATE_ADD(t_fail.txn_time, INTERVAL 2 MINUTE)
GROUP BY 
    t_fail.user_id
HAVING 
    COUNT(*) >= 20
ORDER BY 
    brute_force_pair_count DESC;

-- My findings: Flagged exactly 25 brute-force bot accounts rapidly retrying 
-- credential combinations. Top offender: user 14595 logging 35 rapid-recovery 
-- retry pairs.


-- =====================================================================
-- PATTERN 5: ODD-HOUR CONCENTRATION (Tier 1)
-- What I'm looking for: Bot syndicates operating >= 80% of activity in the
--                       off-peak window (2 AM - 5 AM) with at least 30 total txns.
-- Expected suspects: Exactly 20 users
-- =====================================================================

SELECT 
    user_id,
    COUNT(*) AS total_txns,
    SUM(CASE WHEN HOUR(txn_time) BETWEEN 2 AND 4 THEN 1 ELSE 0 END) AS odd_hour_txns,
    ROUND(SUM(CASE WHEN HOUR(txn_time) BETWEEN 2 AND 4 THEN 1 ELSE 0 END) / COUNT(*), 4) AS odd_hour_ratio
FROM transactions
GROUP BY 
    user_id
HAVING 
    COUNT(*) >= 30 
    AND (SUM(CASE WHEN HOUR(txn_time) BETWEEN 2 AND 4 THEN 1 ELSE 0 END) / COUNT(*)) >= 0.80
ORDER BY 
    odd_hour_ratio DESC, 
    total_txns DESC;

-- My findings: Captured exactly 20 overseas/bot accounts running concentrated 
-- night schedules. Highlight case: user 14608 executed 58 of 63 txns (92.06%) 
-- strictly between 2 AM and 5 AM.


-- =====================================================================
-- PATTERN 6: MULE ACCOUNTS (Tier 2 Advanced)
-- What I'm looking for: Accounts where a CREDIT is drained via a DEBIT of
--                       at least 70% value within 30 minutes (5+ occurrences).
-- Expected suspects: Exactly 30 users
-- =====================================================================

SELECT 
    c.user_id,
    COUNT(DISTINCT c.txn_id) AS rapid_drain_count
FROM transactions c
WHERE 
    c.txn_type = 'CREDIT' 
    AND c.status = 'SUCCESS'
    AND EXISTS (
        SELECT 1 
        FROM transactions d
        WHERE d.user_id = c.user_id
          AND d.txn_type = 'DEBIT'
          AND d.status = 'SUCCESS'
          AND d.txn_time > c.txn_time
          AND d.txn_time <= DATE_ADD(c.txn_time, INTERVAL 30 MINUTE)
          AND d.amount >= (c.amount * 0.70)
    )
GROUP BY 
    c.user_id
HAVING 
    COUNT(DISTINCT c.txn_id) >= 5
ORDER BY 
    rapid_drain_count DESC;

-- My findings: Flagged exactly 30 money mule intermediary accounts used for 
-- high-speed laundering passthroughs. Accounts 14630, 14637, 14640, 14643, 
-- and 14645 all logged 15 rapid cash-in/cash-out sequences.


-- =====================================================================
-- PATTERN 7: REFUND ABUSE (Tier 2)
-- What I'm looking for: Users with >= 20 total transactions having an
--                       abnormal refund ratio exceeding 40%.
-- Expected suspects: 24-25 users
-- =====================================================================

SELECT 
    user_id,
    COUNT(*) AS total_txns,
    SUM(CASE WHEN txn_type = 'REFUND' THEN 1 ELSE 0 END) AS refund_count,
    ROUND(SUM(CASE WHEN txn_type = 'REFUND' THEN 1 ELSE 0 END) / COUNT(*), 4) AS refund_ratio
FROM transactions
GROUP BY 
    user_id
HAVING 
    COUNT(*) >= 20 
    AND (SUM(CASE WHEN txn_type = 'REFUND' THEN 1 ELSE 0 END) / COUNT(*)) > 0.40
ORDER BY 
    refund_ratio DESC, 
    total_txns DESC;

-- My findings: Flagged 24 abusive accounts (within the 24-25 expected range) 
-- exploiting chargeback loopholes. Worst case: user 14657 with 36 refunds 
-- out of 60 total transactions (60.0% refund rate).


-- =====================================================================
-- PATTERN 8: MERCHANT COLLUSION (Tier 2 / CTE & Window Functions)
-- What I'm looking for: Collusive merchants whose top 5 customer accounts
--                       make up over 60% of total processed turnover.
-- Expected suspects: Exactly 15 merchants (merchant IDs 1-15)
-- =====================================================================

WITH merchant_user_totals AS (
    SELECT 
        merchant_id, 
        user_id, 
        SUM(amount) AS user_volume
    FROM transactions
    WHERE status = 'SUCCESS'
    GROUP BY merchant_id, user_id
),
ranked_spenders AS (
    SELECT 
        merchant_id, 
        user_id, 
        user_volume, 
        ROW_NUMBER() OVER (PARTITION BY merchant_id ORDER BY user_volume DESC) AS spend_rank,
        SUM(user_volume) OVER (PARTITION BY merchant_id) AS total_merchant_volume
    FROM merchant_user_totals
),
top5_concentration AS (
    SELECT 
        merchant_id,
        MAX(total_merchant_volume) AS total_volume,
        SUM(CASE WHEN spend_rank <= 5 THEN user_volume ELSE 0 END) AS top5_volume
    FROM ranked_spenders
    GROUP BY merchant_id
)
SELECT 
    merchant_id,
    ROUND(total_volume, 2) AS total_volume,
    ROUND(top5_volume, 2) AS top5_volume,
    ROUND((top5_volume / total_volume) * 100, 2) AS top5_pct_concentration
FROM top5_concentration
WHERE 
    total_volume > 0 
    AND (top5_volume / total_volume) > 0.60
ORDER BY 
    top5_pct_concentration DESC;

-- My findings: Exposed exactly 15 colluding merchant accounts (IDs 1 through 15) 
-- where over 99% of total store revenue was driven by just 5 customer accounts.


-- =====================================================================
-- PATTERN 9: JUST-UNDER-THRESHOLD / STRUCTURING (Tier 2)
-- What I'm looking for: Structuring schemes where users place 10+ transactions
--                       at exactly 9,999.00 to avoid the 10k KYC threshold.
-- Expected suspects: Exactly 20 users
-- =====================================================================

SELECT 
    user_id, 
    COUNT(*) AS structured_txn_count,
    SUM(amount) AS total_structured_amount
FROM transactions
WHERE 
    amount = 9999.00
GROUP BY 
    user_id
HAVING 
    COUNT(*) >= 10
ORDER BY 
    structured_txn_count DESC;

-- My findings: Flagged exactly 20 seeded fraudsters systematically smurfing 
-- amounts. Peak offenders: users 14680 and 14690 with 25 distinct ₹9,999.00 
-- transactions each.


-- =====================================================================
-- PATTERN 10: DORMANT-THEN-ACTIVE (Tier 2 / Window Function LAG)
-- What I'm looking for: Account takeover signature: inactive for 90+ days
--                       followed by 15+ rapid transactions post-reactivation.
-- Expected suspects: 25-27 users
-- =====================================================================

WITH ordered_txns AS (
    SELECT 
        txn_id,
        user_id,
        txn_time,
        LAG(txn_time) OVER (PARTITION BY user_id ORDER BY txn_time) AS prev_txn_time
    FROM transactions
),
gap_identified AS (
    SELECT 
        txn_id,
        user_id,
        txn_time,
        prev_txn_time,
        TIMESTAMPDIFF(DAY, prev_txn_time, txn_time) AS inactivity_days
    FROM ordered_txns
),
first_reactivation AS (
    SELECT 
        user_id,
        MIN(txn_time) AS reactivation_time
    FROM gap_identified
    WHERE inactivity_days >= 90
    GROUP BY user_id
)
SELECT 
    f.user_id,
    f.reactivation_time,
    COUNT(t.txn_id) AS post_dormancy_txns
FROM first_reactivation f
INNER JOIN transactions t 
    ON f.user_id = t.user_id 
    AND t.txn_time >= f.reactivation_time
GROUP BY 
    f.user_id, 
    f.reactivation_time
HAVING 
    COUNT(t.txn_id) >= 15
ORDER BY 
    post_dormancy_txns DESC;

-- My findings: Detected 26 compromised accounts (within the 25-27 expected range). 
-- Clear case: user 14526 completed 55 transactions immediately after a 90+ day 
-- dormant period starting 2024-05-20.


-- =====================================================================
-- PATTERN 11: VELOCITY SPIKE (Tier 3)
-- What I'm looking for: Monthly volume anomaly where peak month activity
--                       is >= 5x higher than historical baseline (peak >= 20).
-- Expected suspects: ~35-45 users
-- =====================================================================

WITH monthly AS (
    SELECT
        user_id,
        DATE_FORMAT(txn_time, '%Y-%m') AS txn_month,
        COUNT(*) AS monthly_count
    FROM transactions
    GROUP BY user_id, txn_month
),
stats AS (
    SELECT
        user_id,
        COUNT(*)           AS active_months,
        MAX(monthly_count) AS peak_monthly,
        SUM(monthly_count) AS total_count
    FROM monthly
    GROUP BY user_id
),
ratios AS (
    SELECT
        user_id,
        peak_monthly,
        (total_count - peak_monthly) / (active_months - 1) AS baseline_avg
    FROM stats
    WHERE active_months >= 4
)
SELECT
    user_id,
    peak_monthly,
    ROUND(baseline_avg, 2) AS baseline_avg,
    ROUND(peak_monthly / baseline_avg, 2) AS spike_ratio
FROM ratios
WHERE peak_monthly >= 20
  AND baseline_avg > 0
  AND (peak_monthly / baseline_avg) >= 5.0
ORDER BY spike_ratio DESC;

-- My findings: Captured 45 suspects (within the expected 35-45 range, covering all 
-- 20 seeded compromised surge accounts plus natural volume burst users). Highest spike: 
-- user 14509 with a baseline of 1 txn/month surging to 36 in one month (36.0x ratio).


-- =====================================================================
-- PATTERN 12: GEOGRAPHIC IMPOSSIBILITY (Tier 3)
-- What I'm looking for: Consecutive transactions across distinct cities
--                       occurring within 60 minutes of each other.
-- Expected suspects: Exactly 15 users
-- =====================================================================

WITH tracked_locations AS (
    SELECT 
        txn_id,
        user_id,
        city,
        txn_time,
        LAG(city) OVER (PARTITION BY user_id ORDER BY txn_time) AS prev_city,
        LAG(txn_time) OVER (PARTITION BY user_id ORDER BY txn_time) AS prev_time
    FROM transactions
    WHERE city IS NOT NULL
)
SELECT 
    user_id,
    COUNT(*) AS impossible_hops_count
FROM tracked_locations
WHERE 
    prev_city IS NOT NULL 
    AND city <> prev_city 
    AND TIMESTAMPDIFF(MINUTE, prev_time, txn_time) <= 60
GROUP BY 
    user_id
HAVING 
    COUNT(*) >= 1
ORDER BY 
    impossible_hops_count DESC;

-- My findings: Identified exactly 15 seeded fraudsters (user IDs 14741 through 14755). 
-- Example: user 14741 recorded consecutive transactions in Vadodara and 
-- Thiruvananthapuram within 30 minutes on 2024-03-13.