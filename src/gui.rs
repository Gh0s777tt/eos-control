//! The Slint GUI half of E-OS Control (Redox-target concern; hosts may build
//! with `--no-default-features` for the CLI/selftest half only).

use crate::security::{db, scan};
use crate::sys;
use slint::{ModelRc, SharedString, Timer, TimerMode, VecModel};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
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
    /// App names whose group is currently expanded. Groups are collapsed by
    /// default (tidy view): one "chrome ×8" row instead of eight scattered ones.
    expanded: HashSet<String>,
}

/// Build a leaf (real process) row. `indent` marks it as nested under a group.
fn leaf_item(p: &sys::Proc, indent: bool) -> ProcItem {
    ProcItem {
        pid: SharedString::from(p.pid.as_str()),
        name: SharedString::from(p.name.as_str()),
        label: SharedString::from(p.label.as_str()),
        owner: SharedString::from(p.owner.as_str()),
        memory: SharedString::from(p.memory.as_str()),
        cpu_time: SharedString::from(p.cpu_time.as_str()),
        caps: SharedString::from(p.resources.join(", ")),
        is_group: false,
        expanded: false,
        indent,
        count: 0,
    }
}

/// Turn a flat process list into grouped rows: apps with more than one instance
/// collapse into a single header ("name ×N", summed memory, union of resources),
/// expandable on demand. Filtering is applied first, then rows are ranked by
/// private memory **descending** (groups by their summed total) so the biggest
/// memory users float to the top — the question a task manager exists to answer.
fn build_rows(procs: Vec<sys::Proc>, needle: &str, expanded: &HashSet<String>) -> Vec<ProcItem> {
    let procs: Vec<sys::Proc> = procs
        .into_iter()
        .filter(|p| {
            needle.is_empty()
                || p.name.to_lowercase().contains(needle)
                || p.label.to_lowercase().contains(needle)
                || p.pid.contains(needle)
        })
        .collect();

    let mut order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, Vec<sys::Proc>> = HashMap::new();
    for p in procs {
        let key = p.name.clone();
        if !groups.contains_key(&key) {
            order.push(key.clone());
        }
        groups.entry(key).or_default().push(p);
    }

    // Rank each app by its total private memory (heaviest first), ties broken by
    // name so refreshes stay deterministic.
    let mut entries: Vec<(u64, String, Vec<sys::Proc>)> = order
        .into_iter()
        .map(|key| {
            let insts = groups.remove(&key).unwrap_or_default();
            let total: u64 = insts.iter().map(|p| p.mem_bytes).sum();
            (total, key, insts)
        })
        .collect();
    entries.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));

    let mut rows: Vec<ProcItem> = Vec::new();
    for (total, key, mut instances) in entries {
        if instances.len() == 1 {
            rows.push(leaf_item(&instances[0], false));
            continue;
        }
        // Group header: summed memory + the union of every instance's resources.
        let mut seen = HashSet::new();
        let mut caps: Vec<String> = Vec::new();
        for p in &instances {
            for r in &p.resources {
                if seen.insert(r.clone()) {
                    caps.push(r.clone());
                }
            }
        }
        let is_expanded = expanded.contains(&key);
        rows.push(ProcItem {
            pid: SharedString::new(),
            name: SharedString::from(key.as_str()),
            label: SharedString::from(crate::labels::describe(&key)),
            owner: SharedString::new(),
            memory: SharedString::from(sys::fmt_bytes(total)),
            cpu_time: SharedString::new(),
            caps: SharedString::from(caps.join(", ")),
            is_group: true,
            expanded: is_expanded,
            indent: false,
            count: instances.len() as i32,
        });
        if is_expanded {
            // Heaviest instance first within the group too.
            instances.sort_by(|a, b| b.mem_bytes.cmp(&a.mem_bytes));
            for p in &instances {
                rows.push(leaf_item(p, true));
            }
        }
    }
    rows
}

fn refresh(win: &MainWindow, state: &State) {
    // Overview tab.
    let ov = sys::overview();
    let mem_total = sys::fmt_bytes(ov.mem_bytes);
    win.set_system(SharedString::from(ov.system.as_str()));
    win.set_cpus(ov.cpus as i32);
    win.set_process_count(ov.processes as i32);
    win.set_mem_total(SharedString::from(mem_total.as_str()));
    win.set_context_switches(SharedString::from(ov.context_switches.to_string()));
    win.set_irqs(SharedString::from(ov.irqs.to_string()));
    win.set_status(SharedString::from(format!(
        "{} procesów · {} pamięci · wg pamięci ↓",
        ov.processes, mem_total
    )));

    // Network tab: the current /etc/net config + whether the stack is up.
    let net = sys::net();
    let dash = |s: &str| SharedString::from(if s.is_empty() { "—" } else { s });
    win.set_net_ip(dash(&net.ip));
    win.set_net_gateway(dash(&net.gateway));
    win.set_net_dns(dash(&net.dns));
    win.set_net_subnet(dash(&net.subnet));
    win.set_net_stack(SharedString::from(if net.stack_up { "aktywny" } else { "brak" }));

    // Storage tab: root-filesystem usage via statvfs.
    let st = sys::storage();
    if st.total_bytes == 0 {
        win.set_disk_total(SharedString::from("—"));
        win.set_disk_used(SharedString::from("—"));
        win.set_disk_free(SharedString::from("—"));
        win.set_disk_pct(SharedString::from("—"));
    } else {
        win.set_disk_total(SharedString::from(sys::fmt_bytes(st.total_bytes)));
        win.set_disk_used(SharedString::from(sys::fmt_bytes(st.used_bytes)));
        win.set_disk_free(SharedString::from(sys::fmt_bytes(st.free_bytes)));
        let pct = ((st.used_bytes as f64 / st.total_bytes as f64) * 100.0).round() as u64;
        win.set_disk_pct(SharedString::from(format!("{pct}%")));
    }

    // Processes tab: filtered, then grouped by app.
    let needle = state.filter.to_lowercase();
    let items = build_rows(sys::processes(), &needle, &state.expanded);
    win.set_procs(ModelRc::new(VecModel::from(items)));
}

/// Open the window and refresh live (every 3 s) until it is closed.
pub fn run() {
    eos_ui::init("E-OS Control");

    let state = Rc::new(RefCell::new(State {
        filter: String::new(),
        expanded: HashSet::new(),
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
    {
        // Expand/collapse a process group; reset the selection so a stale index
        // can't outlive the structure change.
        let (weak, state) = (win.as_weak(), state.clone());
        win.on_toggle(move |name| {
            {
                let mut s = state.borrow_mut();
                let n = name.to_string();
                if !s.expanded.remove(&n) {
                    s.expanded.insert(n);
                }
            }
            if let Some(w) = weak.upgrade() {
                w.set_selected(-1);
                w.set_confirm_kill(false);
                refresh(&w, &state.borrow());
            }
        });
    }
    {
        // Force-kill the confirmed pid (SIGKILL / kernel ForceKill), then refresh.
        let (weak, state) = (win.as_weak(), state.clone());
        win.on_kill(move |pid| {
            let Some(w) = weak.upgrade() else { return };
            let msg = match pid.to_string().trim().parse::<i64>() {
                Ok(p) => match sys::kill(p) {
                    Ok(()) => format!("Zakończono PID {p}."),
                    Err(e) => format!("Błąd: {e}"),
                },
                Err(_) => "Nieprawidłowy PID.".to_string(),
            };
            w.set_kill_status(SharedString::from(msg));
            w.set_selected(-1);
            refresh(&w, &state.borrow());
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
