//! Attachment state machine — tracks confidence progression per MAC.
//!
//! States: Unknown → Candidate (1 win) → Probable (3 wins) → Stable (10 wins)
//! Plus: Roaming, Conflicted, HumanPinned.

use serde::Serialize;

/// The attachment state kind.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum AttachmentStateKind {
    Unknown,
    Candidate,
    Probable,
    Stable,
    Roaming,
    Conflicted,
    HumanPinned,
}

impl AttachmentStateKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Candidate => "candidate",
            Self::Probable => "probable",
            Self::Stable => "stable",
            Self::Roaming => "roaming",
            Self::Conflicted => "conflicted",
            Self::HumanPinned => "human_pinned",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "candidate" => Self::Candidate,
            "probable" => Self::Probable,
            "stable" => Self::Stable,
            "roaming" => Self::Roaming,
            "conflicted" => Self::Conflicted,
            "human_pinned" => Self::HumanPinned,
            _ => Self::Unknown,
        }
    }
}

/// Full attachment state for a MAC address.
#[derive(Debug, Clone, Serialize)]
pub struct AttachmentState {
    pub mac_address: String,
    pub state: AttachmentStateKind,
    pub current_device_id: Option<String>,
    pub current_port_name: Option<String>,
    pub previous_device_id: Option<String>,
    pub previous_port_name: Option<String>,
    pub current_score: f64,
    pub confidence: f64,
    pub consecutive_wins: u32,
    pub consecutive_losses: u32,
    pub updated_at: i64,
}

/// Hysteresis thresholds (from spec answers).
const WIRED_HYSTERESIS_MULTIPLIER: f64 = 1.25;
const WIRED_LOSS_THRESHOLD: u32 = 2;
const WIRELESS_HYSTERESIS_MULTIPLIER: f64 = 1.10;
const WIRELESS_LOSS_THRESHOLD: u32 = 1;

/// Promotion thresholds (cycle counts).
const PROMOTE_TO_CANDIDATE: u32 = 1;
const PROMOTE_TO_PROBABLE: u32 = 3;
const PROMOTE_TO_STABLE: u32 = 10;

/// Score decay per cycle when no challenger beats the current score.
const SCORE_DECAY: f64 = 0.98;

/// Belief update: exponential moving average weight.
const BELIEF_WEIGHT_PREVIOUS: f64 = 0.7;
const BELIEF_WEIGHT_NEW: f64 = 0.3;

impl AttachmentState {
    /// Create a new unknown state for a MAC.
    pub fn new(mac: &str) -> Self {
        Self {
            mac_address: mac.to_string(),
            state: AttachmentStateKind::Unknown,
            current_device_id: None,
            current_port_name: None,
            previous_device_id: None,
            previous_port_name: None,
            current_score: 0.0,
            confidence: 0.0,
            consecutive_wins: 0,
            consecutive_losses: 0,
            updated_at: 0,
        }
    }

    /// Update the state with a new winner from the scoring engine.
    ///
    /// Returns true if the binding changed (new device/port).
    pub fn update(
        &mut self,
        winner_device: &str,
        winner_port: &str,
        winner_score: f64,
        confidence: f64,
        is_wireless: bool,
        now_ts: i64,
    ) -> bool {
        self.updated_at = now_ts;

        // Human-pinned states can only be overridden by explicit human action
        if self.state == AttachmentStateKind::HumanPinned {
            return false;
        }

        let same_binding = self.current_device_id.as_deref() == Some(winner_device)
            && self.current_port_name.as_deref() == Some(winner_port);

        if same_binding {
            // Same binding wins again — reinforce
            self.consecutive_wins = self.consecutive_wins.saturating_add(1);
            self.consecutive_losses = 0;

            // Belief update: EMA
            self.current_score = BELIEF_WEIGHT_PREVIOUS * self.current_score
                + BELIEF_WEIGHT_NEW * winner_score;
            self.confidence = confidence;

            // Promote if thresholds met
            self.maybe_promote();
            false
        } else if self.current_device_id.is_none() {
            // First binding ever — accept immediately
            self.current_device_id = Some(winner_device.to_string());
            self.current_port_name = Some(winner_port.to_string());
            self.current_score = winner_score;
            self.confidence = confidence;
            self.consecutive_wins = 1;
            self.consecutive_losses = 0;
            self.state = AttachmentStateKind::Candidate;
            true
        } else {
            // Different binding — check hysteresis
            let (multiplier, loss_threshold) = if is_wireless {
                (WIRELESS_HYSTERESIS_MULTIPLIER, WIRELESS_LOSS_THRESHOLD)
            } else {
                (WIRED_HYSTERESIS_MULTIPLIER, WIRED_LOSS_THRESHOLD)
            };

            // Apply score decay to current binding
            self.current_score *= SCORE_DECAY;

            // Challenger must beat current × multiplier
            if winner_score > self.current_score * multiplier {
                self.consecutive_losses = self.consecutive_losses.saturating_add(1);

                if self.consecutive_losses >= loss_threshold {
                    // Binding changes — save previous for roaming detection
                    self.previous_device_id = self.current_device_id.take();
                    self.previous_port_name = self.current_port_name.take();
                    self.current_device_id = Some(winner_device.to_string());
                    self.current_port_name = Some(winner_port.to_string());
                    self.current_score = winner_score;
                    self.confidence = confidence;
                    self.consecutive_wins = 1;
                    self.consecutive_losses = 0;
                    self.state = AttachmentStateKind::Candidate;
                    true
                } else {
                    // Not enough consecutive losses — retain current binding
                    // but mark as potentially conflicted if in stable state
                    false
                }
            } else {
                // Challenger doesn't beat hysteresis — current binding holds
                self.consecutive_losses = 0;
                self.consecutive_wins = self.consecutive_wins.saturating_add(1);
                self.current_score = BELIEF_WEIGHT_PREVIOUS * self.current_score
                    + BELIEF_WEIGHT_NEW * winner_score.min(self.current_score);
                self.maybe_promote();
                false
            }
        }
    }

    /// Promote state based on consecutive win count.
    fn maybe_promote(&mut self) {
        if self.consecutive_wins >= PROMOTE_TO_STABLE
            && self.state != AttachmentStateKind::Stable
        {
            self.state = AttachmentStateKind::Stable;
        } else if self.consecutive_wins >= PROMOTE_TO_PROBABLE
            && self.state == AttachmentStateKind::Candidate
        {
            self.state = AttachmentStateKind::Probable;
        } else if self.consecutive_wins >= PROMOTE_TO_CANDIDATE
            && self.state == AttachmentStateKind::Unknown
        {
            self.state = AttachmentStateKind::Candidate;
        }
    }

    /// Pin the binding as human-confirmed (cannot be overridden by inference).
    #[allow(dead_code)]
    pub fn pin_human(&mut self, device_id: &str, port_name: &str, now_ts: i64) {
        self.current_device_id = Some(device_id.to_string());
        self.current_port_name = Some(port_name.to_string());
        self.state = AttachmentStateKind::HumanPinned;
        self.confidence = 1.0;
        self.consecutive_wins = 0;
        self.consecutive_losses = 0;
        self.updated_at = now_ts;
    }
}
