use lazy_static::lazy_static;
use prometheus::{Histogram, IntCounter, IntCounterVec, IntGauge};

lazy_static! {
    pub static ref MESSAGES_TOTAL: IntCounterVec = prometheus::register_int_counter_vec!(
        prometheus::opts!("zumble_messages_total", "number of messages"),
        &["protocol", "direction", "kind"]
    )
    .expect("can't create a metric");
    pub static ref MESSAGES_BYTES: IntCounterVec =
        prometheus::register_int_counter_vec!(prometheus::opts!("zumble_messages_bytes", "message bytes"), &["protocol", "direction", "kind"])
            .expect("can't create a metric");
    pub static ref CLIENTS_TOTAL: IntGauge =
        prometheus::register_int_gauge!(prometheus::opts!("zumble_clients_total", "Total number of clients")).expect("can't create a metric");
    pub static ref UNKNOWN_MESSAGES_TOTAL: IntCounterVec = prometheus::register_int_counter_vec!(
        prometheus::opts!(
            "zumble_unknown_messages_total",
            "number of unknown messages (sent from clients not initialized)"
        ),
        &["protocol", "direction", "kind"]
    )
    .expect("can't create a metric");
    pub static ref UNKNOWN_MESSAGES_BYTES: IntCounterVec = prometheus::register_int_counter_vec!(
        prometheus::opts!(
            "zumble_unknown_messages_bytes",
            "unknown message bytes (sent from clients not initialized)"
        ),
        &["protocol", "direction", "kind"]
    )
    .expect("can't create a metric");
    
    // New crypto-related metrics
    pub static ref CRYPT_RESETS_TOTAL: IntCounter = 
        prometheus::register_int_counter!(prometheus::opts!("zumble_crypt_resets_total", "Total crypt state resets")).expect("can't create metric");
    
    pub static ref CRYPT_ERRORS_TOTAL: IntCounterVec = 
        prometheus::register_int_counter_vec!(
            prometheus::opts!("zumble_crypt_errors_total", "Total crypt errors by type"), 
            &["error_type"]
        ).expect("can't create metric");
    
    pub static ref NONCE_WRAPS_TOTAL: IntCounter = 
        prometheus::register_int_counter!(prometheus::opts!("zumble_nonce_wraps_total", "Total nonce wrap events")).expect("can't create metric");
    
    pub static ref LATE_PACKETS_TOTAL: IntCounter = 
        prometheus::register_int_counter!(prometheus::opts!("zumble_late_packets_total", "Total late packets received")).expect("can't create metric");
    
    pub static ref LOST_PACKETS_TOTAL: IntCounter = 
        prometheus::register_int_counter!(prometheus::opts!("zumble_lost_packets_total", "Total lost packets detected")).expect("can't create metric");
}
