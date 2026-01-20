use std::collections::HashMap;
use std::time::{Duration, SystemTime};

// Circuit breaker thresholds
const CIRCUIT_1HR_THRESHOLD: usize = 10;      // 10 negative actions in 1 hour trips circuit
const CIRCUIT_24HR_THRESHOLD: usize = 50;     // 50 negative actions in 24 hours trips circuit
const CIRCUIT_7DAY_THRESHOLD: usize = 200;    // 200 negative actions in 7 days trips circuit
const CIRCUIT_COOLDOWN_HOURS: u64 = 24;       // How long circuit stays tripped

const COORDINATION_MIN_USERS: usize = 5;      // Minimum users to check for coordination
const COORDINATION_THRESHOLD: f64 = 0.6;      // 60% overlap = coordinated attack

#[derive(Debug, Clone)]
pub struct NegativeAction {
    pub user_id: u64,
    pub target_id: u64,
    pub action_type: NegativeActionType,
    pub timestamp: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NegativeActionType {
    Block,
    Mute,
    Report,
    NotInterested,
}

#[derive(Debug, Clone)]
pub struct CircuitState {
    pub is_tripped: bool,
    pub tripped_at: Option<SystemTime>,
    pub reason: String,
    pub action_count_1hr: usize,
    pub action_count_24hr: usize,
    pub action_count_7day: usize,
}

pub struct ProtectionCircuit {
    // Track all negative actions by target
    target_actions: HashMap<u64, Vec<NegativeAction>>,
    // Track circuit state for each target
    circuit_states: HashMap<u64, CircuitState>,
}

impl ProtectionCircuit {
    pub fn new() -> Self {
        Self {
            target_actions: HashMap::new(),
            circuit_states: HashMap::new(),
        }
    }

    /// Main check: should this negative action count or be ignored?
    pub fn should_count_action(&mut self, action: NegativeAction) -> CircuitDecision {
        // Clean up old data
        self.cleanup_expired_data();
        
        // Check if circuit is already tripped for this target
        if let Some(state) = self.circuit_states.get(&action.target_id) {
            if state.is_tripped {
                if self.is_circuit_cooled_down(&state) {
                    // Circuit has cooled down, reset it
                    self.reset_circuit(action.target_id);
                } else {
                    // Circuit still tripped - don't count this action
                    return CircuitDecision {
                        count_action: false,
                        circuit_tripped: true,
                        reason: state.reason.clone(),
                        state: state.clone(),
                    };
                }
            }
        }
        
        // Add this action to history
        self.record_action(action.clone());
        
        // Check if this new action trips the circuit
        let state = self.evaluate_circuit(action.target_id);
        
        if state.is_tripped {
            // Circuit just tripped - don't count this or future actions
            self.circuit_states.insert(action.target_id, state.clone());
            
            CircuitDecision {
                count_action: false,
                circuit_tripped: true,
                reason: state.reason.clone(),
                state,
            }
        } else {
            // Circuit not tripped - count the action normally
            CircuitDecision {
                count_action: true,
                circuit_tripped: false,
                reason: "Action counted normally".to_string(),
                state,
            }
        }
    }

    /// Evaluate if circuit should trip based on action velocity
    fn evaluate_circuit(&self, target_id: u64) -> CircuitState {
        let actions = match self.target_actions.get(&target_id) {
            Some(a) => a,
            None => return CircuitState::default(),
        };

        let now = SystemTime::now();
        
        // Count actions in different time windows
        let count_1hr = self.count_actions_in_window(actions, now, Duration::from_secs(3600));
        let count_24hr = self.count_actions_in_window(actions, now, Duration::from_secs(86400));
        let count_7day = self.count_actions_in_window(actions, now, Duration::from_secs(604800));
        
        // Check if any threshold is exceeded
        if count_1hr >= CIRCUIT_1HR_THRESHOLD {
            return CircuitState {
                is_tripped: true,
                tripped_at: Some(now),
                reason: format!("Circuit tripped: {} actions in 1 hour (threshold: {})", 
                    count_1hr, CIRCUIT_1HR_THRESHOLD),
                action_count_1hr: count_1hr,
                action_count_24hr: count_24hr,
                action_count_7day: count_7day,
            };
        }
        
        if count_24hr >= CIRCUIT_24HR_THRESHOLD {
            // Also check for coordination
            let is_coordinated = self.check_coordination(actions, Duration::from_secs(86400));
            let reason = if is_coordinated {
                format!("Circuit tripped: {} coordinated actions in 24 hours (threshold: {})", 
                    count_24hr, CIRCUIT_24HR_THRESHOLD)
            } else {
                format!("Circuit tripped: {} actions in 24 hours (threshold: {})", 
                    count_24hr, CIRCUIT_24HR_THRESHOLD)
            };
            
            return CircuitState {
                is_tripped: true,
                tripped_at: Some(now),
                reason,
                action_count_1hr: count_1hr,
                action_count_24hr: count_24hr,
                action_count_7day: count_7day,
            };
        }
        
        if count_7day >= CIRCUIT_7DAY_THRESHOLD {
            return CircuitState {
                is_tripped: true,
                tripped_at: Some(now),
                reason: format!("Circuit tripped: {} actions in 7 days (threshold: {})", 
                    count_7day, CIRCUIT_7DAY_THRESHOLD),
                action_count_1hr: count_1hr,
                action_count_24hr: count_24hr,
                action_count_7day: count_7day,
            };
        }
        
        // Circuit not tripped
        CircuitState {
            is_tripped: false,
            tripped_at: None,
            reason: "Circuit normal".to_string(),
            action_count_1hr: count_1hr,
            action_count_24hr: count_24hr,
            action_count_7day: count_7day,
        }
    }

    /// Check if multiple users are coordinating attacks (targeting same set of users)
    fn check_coordination(&self, actions: &[NegativeAction], window: Duration) -> bool {
        let now = SystemTime::now();
        let cutoff = now - window;
        
        // Get recent actions in window
        let recent: Vec<_> = actions.iter()
            .filter(|a| a.timestamp > cutoff)
            .collect();
        
        if recent.len() < COORDINATION_MIN_USERS {
            return false;
        }
        
        // Get unique user IDs
        let unique_users: std::collections::HashSet<_> = recent.iter()
            .map(|a| a.user_id)
            .collect();
        
        if unique_users.len() < COORDINATION_MIN_USERS {
            return false;
        }
        
        // Build target sets for each user (what else are they targeting?)
        let mut user_target_sets: HashMap<u64, std::collections::HashSet<u64>> = HashMap::new();
        
        for user_id in unique_users.iter() {
            let mut targets = std::collections::HashSet::new();
            
            // Look at all targets this user has acted against
            for (target_id, target_actions) in self.target_actions.iter() {
                for action in target_actions.iter() {
                    if action.user_id == *user_id && action.timestamp > cutoff {
                        targets.insert(*target_id);
                    }
                }
            }
            
            user_target_sets.insert(*user_id, targets);
        }
        
        // Calculate average overlap between users' target lists
        let users_vec: Vec<_> = unique_users.iter().collect();
        let mut total_similarity = 0.0;
        let mut pair_count = 0;
        
        for i in 0..users_vec.len() {
            for j in (i + 1)..users_vec.len() {
                if let (Some(set_a), Some(set_b)) = 
                    (user_target_sets.get(users_vec[i]), user_target_sets.get(users_vec[j])) {
                    
                    let intersection = set_a.intersection(set_b).count();
                    let union = set_a.union(set_b).count();
                    
                    if union > 0 {
                        total_similarity += intersection as f64 / union as f64;
                        pair_count += 1;
                    }
                }
            }
        }
        
        if pair_count > 0 {
            let avg_similarity = total_similarity / pair_count as f64;
            avg_similarity >= COORDINATION_THRESHOLD
        } else {
            false
        }
    }

    fn count_actions_in_window(&self, actions: &[NegativeAction], now: SystemTime, window: Duration) -> usize {
        let cutoff = now - window;
        actions.iter().filter(|a| a.timestamp > cutoff).count()
    }

    fn is_circuit_cooled_down(&self, state: &CircuitState) -> bool {
        if let Some(tripped_at) = state.tripped_at {
            let elapsed = SystemTime::now()
                .duration_since(tripped_at)
                .unwrap_or(Duration::from_secs(0));
            
            elapsed > Duration::from_secs(CIRCUIT_COOLDOWN_HOURS * 3600)
        } else {
            true
        }
    }

    fn reset_circuit(&mut self, target_id: u64) {
        self.circuit_states.remove(&target_id);
    }

    fn record_action(&mut self, action: NegativeAction) {
        self.target_actions
            .entry(action.target_id)
            .or_insert_with(Vec::new)
            .push(action);
    }

    fn cleanup_expired_data(&mut self) {
        let cutoff = SystemTime::now() - Duration::from_secs(604800); // Keep 7 days
        
        // Clean old actions
        for actions in self.target_actions.values_mut() {
            actions.retain(|a| a.timestamp > cutoff);
        }
        
        // Remove empty entries
        self.target_actions.retain(|_, v| !v.is_empty());
        
        // Clean cooled-down circuits
        self.circuit_states.retain(|_, state| {
            !self.is_circuit_cooled_down(state)
        });
    }

    /// Get current circuit status for a target
    pub fn get_circuit_status(&self, target_id: u64) -> CircuitState {
        self.circuit_states.get(&target_id)
            .cloned()
            .unwrap_or_default()
    }
}

#[derive(Debug)]
pub struct CircuitDecision {
    pub count_action: bool,        // Should this action affect visibility scores?
    pub circuit_tripped: bool,     // Is circuit currently tripped?
    pub reason: String,
    pub state: CircuitState,
}

impl Default for CircuitState {
    fn default() -> Self {
        Self {
            is_tripped: false,
            tripped_at: None,
            reason: "No data".to_string(),
            action_count_1hr: 0,
            action_count_24hr: 0,
            action_count_7day: 0,
        }
    }
}

/// Integration with your Phoenix scoring system
pub fn apply_circuit_protection(
    scores: &mut PhoenixScores,
    decision: &CircuitDecision,
) {
    if !decision.count_action {
        // Circuit tripped - zero out negative action scores
        scores.not_interested_score = 0.0;
        scores.block_author_score = 0.0;
        scores.mute_author_score = 0.0;
        scores.report_score = 0.0;
    }
    // If count_action is true, scores remain as-is
}

// Your existing PhoenixScores struct
#[derive(Debug)]
pub struct PhoenixScores {
    pub favorite_score: f64,
    pub reply_score: f64,
    pub retweet_score: f64,
    pub photo_expand_score: f64,
    pub click_score: f64,
    pub profile_click_score: f64,
    pub vqv_score: f64,
    pub share_score: f64,
    pub share_via_dm_score: f64,
    pub share_via_copy_link_score: f64,
    pub dwell_score: f64,
    pub quote_score: f64,
    pub quoted_click_score: f64,
    pub follow_author_score: f64,
    pub not_interested_score: f64,
    pub block_author_score: f64,
    pub mute_author_score: f64,
    pub report_score: f64,
    pub dwell_time: f64,
}