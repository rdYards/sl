use std::{
    time::{SystemTime, UNIX_EPOCH},
};

pub fn return_time() -> String {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");

    let seconds = since_the_epoch.as_secs();
    let nanos = since_the_epoch.subsec_nanos();

    // Convert seconds to hours, minutes, seconds
    let hours = (seconds % 86400) / 3600;
    let minutes = (seconds % 3600) / 60;
    let seconds = seconds % 60;

    format!(
        "{:02}:{:02}:{:02}.{:09} UTC",
        hours, minutes, seconds, nanos
    )
}
