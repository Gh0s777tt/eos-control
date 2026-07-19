//! The Slint GUI half of E-OS Control (Redox-target concern; hosts may build
//! with `--no-default-features` for the CLI/selftest half only).

use crate::security::{db, scan};
use crate::sys;
use slint::{ModelRc, SharedString, Timer, TimerMode, VecModel};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

slint::include_modules!();

/// Cap the number of files a single Security scan hashes, so pointing it at a
/// huge tree can't wedge the single-threaded event loop.
const SCAN_BUDGET: usize = 20_000;

fn parse_roots(s: &str) -> Vec<String> {
    s.split(',')
        .map(|r| r.trim())
        .filter(|r| !r.is_empty())
        .map(str::to_string)
        .collect()
}

fn kind_of(s: db::Status) -> i32 {
    match s {
        db::Status::Ok => 0,
        db::Status::New => 1,
        db::Status::Modified => 2,
        db::Status::Removed => 3,
        db::Status::Warn => 4,
    }
}

fn show_findings(win: &MainWindow, findings: &[db::Finding]) {
    let items: Vec<Finding> = findings
        .iter()
        .map(|f| Finding {
            path: SharedString::from(f.path.as_str()),
            status: SharedString::from(f.status.label()),
            detail: SharedString::from(f.detail.as_str()),
            kind: kind_of(f.status),
        })
        .collect();
    win.set_findings(ModelRc::new(VecModel::from(items)));
}

/// The GUI-side state that outlives a single refresh.
struct State {
    filter: String,
}

fn refresh(win: &MainWindow, state: &State) {
    // Overview tab.
    let ov = sys::overview();
    win.set_system(SharedString::from(ov.system.as_str()));
    win.set_cpus(ov.cpus as i32);
    win.set_process_count(ov.processes as i32);
    win.set_context_switches(SharedString::from(ov.context_switches.to_string()));
    win.set_irqs(SharedString::from(ov.irqs.to_string()));
    win.set_status(SharedString::from(format!("{} procesów", ov.processes)));

    // Processes tab, filtered.
    let needle = state.filter.to_lowercase();
    let items: Vec<ProcItem> = sys::processes()
        .into_iter()
        .filter(|p| {
            needle.is_empty()
                || p.name.to_lowercase().contains(&needle)
                || p.label.to_lowercase().contains(&needle)
                || p.pid.contains(&needle)
        })
        .map(|p| ProcItem {
            pid: SharedString::from(p.pid.as_str()),
            name: SharedString::from(p.name.as_str()),
            label: SharedString::from(p.label.as_str()),
            owner: SharedString::from(p.owner.as_str()),
            memory: SharedString::from(p.memory.as_str()),
            cpu_time: SharedString::from(p.cpu_time.as_str()),
            caps: SharedString::from(p.resources.join(", ")),
        })
        .collect();
    win.set_procs(ModelRc::new(VecModel::from(items)));
}

/// Open the window and refresh live (every 3 s) until it is closed.
pub fn run() {
    eos_ui::init("E-OS Control");

    let state = Rc::new(RefCell::new(State {
        filter: String::new(),
    }));
    let win = MainWindow::new().expect("eos-control: cannot create the window");
    refresh(&win, &state.borrow());

    {
        let (weak, state) = (win.as_weak(), state.clone());
        win.on_refresh(move || {
            if let Some(w) = weak.upgrade() {
                refresh(&w, &state.borrow());
            }
        });
    }
    {
        let weak = win.as_weak();
        win.on_select(move |i| {
            if let Some(w) = weak.upgrade() {
                w.set_selected(i);
            }
        });
    }
    {
        let (weak, state) = (win.as_weak(), state.clone());
        win.on_filter_changed(move |text| {
            state.borrow_mut().filter = text.to_string();
            if let Some(w) = weak.upgrade() {
                w.set_selected(-1);
                refresh(&w, &state.borrow());
            }
        });
    }

    // ── Security tab ─────────────────────────────────────────────
    // One baseline DB shared by both actions; None if it can't be opened.
    let sdb: Rc<RefCell<Option<db::Db>>> =
        Rc::new(RefCell::new(db::Db::open(&db::default_path()).ok()));
    if let Some(d) = sdb.borrow().as_ref() {
        let n = d.baseline_count().unwrap_or(0);
        let intact = d.verify_baseline().unwrap_or(true);
        win.set_sec_status(SharedString::from(if n == 0 {
            "Brak wzorca — kliknij „Ustaw wzorzec”.".to_string()
        } else if !intact {
            format!("⚠ Wzorzec ({n} plików) NARUSZONY — ustaw ponownie.")
        } else {
            format!("Wzorzec: {n} plików. Kliknij Skanuj.")
        }));
    }
    {
        let (weak, sdb) = (win.as_weak(), sdb.clone());
        win.on_baseline(move || {
            let Some(w) = weak.upgrade() else { return };
            let roots = parse_roots(w.get_roots().as_str());
            if roots.is_empty() {
                w.set_sec_status(SharedString::from("Podaj przynajmniej jeden katalog."));
                return;
            }
            let (entries, truncated) = scan::scan_roots(&roots, SCAN_BUDGET);
            let n = entries.len();
            match sdb.borrow_mut().as_mut().map(|d| d.set_baseline(&entries)) {
                Some(Ok(())) => w.set_sec_status(SharedString::from(format!(
                    "Wzorzec ustawiony: {n} plików{}.",
                    if truncated { " (obcięto)" } else { "" }
                ))),
                _ => w.set_sec_status(SharedString::from("Błąd zapisu wzorca.")),
            }
            show_findings(&w, &[]);
        });
    }
    {
        let (weak, sdb) = (win.as_weak(), sdb.clone());
        win.on_scan(move || {
            let Some(w) = weak.upgrade() else { return };
            let borrow = sdb.borrow();
            let Some(d) = borrow.as_ref() else {
                w.set_sec_status(SharedString::from("Baza wzorca niedostępna."));
                return;
            };
            if d.baseline_count().unwrap_or(0) == 0 {
                w.set_sec_status(SharedString::from(
                    "Brak wzorca — najpierw „Ustaw wzorzec”.",
                ));
                return;
            }
            let roots = parse_roots(w.get_roots().as_str());
            let (entries, truncated) = scan::scan_roots(&roots, SCAN_BUDGET);
            let intact = d.verify_baseline().unwrap_or(true);
            match d.diff(&entries) {
                Ok((findings, sum)) => {
                    let changed = sum.new + sum.modified + sum.removed + sum.warn;
                    show_findings(&w, &findings);
                    w.set_sec_status(SharedString::from(format!(
                        "Przeskanowano {} plików: {} zmian/ostrzeżeń{}.{}",
                        entries.len(),
                        changed,
                        if truncated { " (obcięto)" } else { "" },
                        if intact {
                            ""
                        } else {
                            "  ⚠ WZORZEC NARUSZONY"
                        }
                    )));
                }
                Err(e) => w.set_sec_status(SharedString::from(format!("Błąd skanu: {e}"))),
            }
        });
    }

    // Live updates: the orbital event loop drives Slint timers.
    let timer = Timer::default();
    {
        let (weak, state) = (win.as_weak(), state.clone());
        timer.start(TimerMode::Repeated, Duration::from_secs(3), move || {
            if let Some(w) = weak.upgrade() {
                refresh(&w, &state.borrow());
            }
        });
    }

    win.run().expect("eos-control: event loop failed");
    drop(timer);
}
