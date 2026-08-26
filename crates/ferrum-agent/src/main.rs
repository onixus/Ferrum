//! Node agent. Last-known-good bundle, never fail-open if CP dies.

use ferrum_agent::{Agent, AgentConfig};
use ferrum_common::FerrumError;

fn main() {
    let mut agent = Agent::new(AgentConfig::default());
    if let Err(err) = agent.restore_last_known_good() {
        eprintln!("ferrum-agent: {err}");
    }
    match agent.attach_pins() {
        Ok(()) => {}
        Err(FerrumError::Degraded(reason)) => {
            eprintln!("ferrum-agent: {reason}");
            std::process::exit(2);
        }
        Err(err) => {
            eprintln!("ferrum-agent: {err}");
            std::process::exit(2);
        }
    }
}
