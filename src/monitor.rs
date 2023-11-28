use sysinfo::{ProcessExt, SystemExt};
use regex::Regex;
use std::{process};
use widestring::WideCString;
use walkdir::WalkDir;
use std::io;
use std::env;

use crate::process_module;

pub fn detect_logitech_scripts() -> io::Result<bool> {
    let t = env::home_dir().unwrap();

    let mut contains_scripts = false;

    for entry in WalkDir::new(t.into_os_string().into_string().unwrap() + "\\AppData\\Local\\LGHUB") {
            // if sf_child.is_some() {
            //         sf_child.take().unwrap().kill().expect("!kill");
            //     }
          
        let re = Regex::new(r"^.*\.(lua)$").unwrap();
                
        let entry = entry.unwrap();
        if re.is_match(entry.file_name().to_str().unwrap()) {
            println!("Detected script {}", entry.path().display());
            contains_scripts = true;
            break;
        }
    }

    Ok(contains_scripts)
}

pub fn monitor_processes(sf_spawned : &mut bool) -> bool {
    let mut system = sysinfo::System::new_all();

    system.refresh_all();

    let re = Regex::new(r"hack|scr_001|injector
        |wallhack|aimbot|cheat engine|x96dbg|x64dbg|process hacker|ollydbg|ksf_loader").unwrap();

    let mut found_sf : bool = false;

    for (_pid, process) in system.get_processes() {
        let opt_exe = process.exe().to_str();

        if process.name().to_lowercase() == ".exe"{
            found_sf = true
        }

        if re.is_match(&process.name().to_lowercase()) || (opt_exe.is_some() && re.is_match(&opt_exe.unwrap().to_lowercase())) {
           // println!("PID = {} Name = {} => EXE: {:?}, CMD = {:?}", pid, process.name(), process.exe(), process.cmd());

            if process.name() != ".exe" 
                && process.name() != "guardian.exe" 
                && process.name() != ".exe"
                && process.name() != "xxd-0.xem" 
                && process.name() != "openvpn.exe" {
                println!("Monitor[1] - {}", process.name());

                if opt_exe.is_some() {
                    println!("Monitor[1.1] - {}", opt_exe.unwrap().to_lowercase());
                }
                
                return false;
            }
        }
    }

    if *sf_spawned && !found_sf {
        println!("SF died :(");
        process::exit(35);
    }

    return true;
}

// Get the modules found at the start
// and x amount of time check for any ones

pub fn dll_inject_checker(module_results: &mut Vec<process_module::ModuleResult>, pid : u32) -> bool {
    let modules: Vec<process_module::ModuleResult> = process_module::get_modules(pid);

    if modules.len() != module_results.len() {
        println!("Monitor[2] Modules did not match {:?} - {:?}", modules.len(), module_results.len() );
        return false;
    }

    let mut new_modules: Vec<WideCString> = Vec::new();

    for x in modules {
        let mut found : bool = false;
        for k in &mut *module_results {
            if k.exe_path == x.exe_path && k.module_name == x.module_name {
                found = true;
                break;
            }
        }

        if !found {
            println!("Monitor[2.1] - Did not exist before {:?}", x.module_name);
            new_modules.push(x.module_name);
        }
    }

    return new_modules.len() == 0;
}
