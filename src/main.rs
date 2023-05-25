use std::time::Duration;
use std::thread;

fn main() {
    loop {
        println!("no threat sources observed");
        thread::sleep(Duration::from_millis(10000))
    }
}
