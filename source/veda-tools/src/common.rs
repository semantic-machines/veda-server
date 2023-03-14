use std::thread;
use std::time::Duration as std_Duration;
use systemstat::{Platform, System};

pub fn pause_if_overload(sys: &System, max_load: usize) {
    loop {
        match sys.load_average() {
            Ok(loadavg) => {
                if loadavg.one > max_load as f32 {
                    info!("Load average one: {} > {}, sleep", loadavg.one, max_load);
                    thread::sleep(std_Duration::from_millis(10000));
                } else {
                    break;
                }
            },
            Err(x) => {
                info!("\nLoad average: error: {}", x);
                break;
            },
        }
    }
}
