//! E-OS Control — the unified Crimson control center for E-OS.
//!
//! One app, three tabs: **Overview** (system health), **Processes** (a task
//! manager with a per-process capability inspector and human labels), and
//! **Security** (integrity + permission audit). It consolidates what would
//! otherwise be several small tools — because on a capability-secure microkernel
//! *what a process can touch* is at once its resource profile and its security
//! profile, so monitoring and security are two views of one truth.
//!
//! GUI (Slint over the shared `eos-ui` backend) is behind the default `gui`
//! feature — a Redox-target concern; `--selftest` proves the read cores headlessly.

#[cfg(feature = "gui")]
mod gui;
mod labels;
mod security;
mod selftest;
mod sys;

fn main() {
    if std::env::args().any(|a| a == "--selftest") {
        match selftest::run() {
            Ok(()) => {
                println!("EOS-CONTROL-SELFTEST-OK");
                eprintln!("EOS-CONTROL-SELFTEST-OK");
            }
            Err(err) => {
                println!("EOS-CONTROL-SELFTEST-FAIL: {err}");
                eprintln!("EOS-CONTROL-SELFTEST-FAIL: {err}");
                std::process::exit(1);
            }
        }
        return;
    }

    #[cfg(feature = "gui")]
    gui::run();

    #[cfg(not(feature = "gui"))]
    {
        let ov = sys::overview();
        println!(
            "{} · {} CPUs · {} processes",
            ov.system, ov.cpus, ov.processes
        );
    }
}
