use ferrum_proto::EnforcementEvent;

pub trait EventSink {
    fn emit(&self, event: &EnforcementEvent);
}

pub struct StdoutSink;

impl EventSink for StdoutSink {
    fn emit(&self, event: &EnforcementEvent) {
        let _ = event;
    }
}
