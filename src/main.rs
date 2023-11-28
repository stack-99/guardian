extern crate widestring;
extern crate pe;

use sysinfo::{ProcessExt, SystemExt};
use std::{process, env};
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::ffi::{CString};
use widestring::WideCString;
use std::ffi::OsString;
use winreg::enums::*;
use winreg::RegKey;
use std::ptr::null_mut;
use async_std::task;
use winapi::um::winnt::HANDLE;

use winapi::um::handleapi::{
    CloseHandle
};

use winapi::um::processenv::{
    SetEnvironmentVariableA
};

use winapi;

mod process_module;

mod inject;

mod monitor;
//use winapi::shared::minwindef::{BOOL, DWORD, LPVOID};

fn hide_console_window() {
    use std::ptr;
    use winapi::um::wincon::GetConsoleWindow;
    use winapi::um::winuser::{ShowWindow, SW_HIDE};

    let window = unsafe {GetConsoleWindow()};
    // https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-showwindow
    if window != ptr::null_mut() {
        unsafe {
            ShowWindow(window, SW_HIDE);
        }
    }
}

fn get_sf_pid() -> u32 {
    let mut system = sysinfo::System::new_all();

    system.refresh_all();

    for (_pid, process) in system.get_processes() {

        if process.name().to_lowercase() == ".exe" {
            return *_pid as u32;
        }
    }

    return 0
}

fn is_sf_loaded() -> bool {
    return get_sf_pid() != 0;
}

fn inject_dll(path : OsString) -> bool {
    let dll_path: &Path = Path::new(&path);

    if !dll_path.exists() {
        println!("DLL file specified does not exist: {:?}", dll_path);
        return false;
    }

    let dll_path_buf: PathBuf = std::fs::canonicalize(dll_path).unwrap();
    let dll_path_real: &Path = Path::new(dll_path_buf.as_path());

    let mut process_ids: Vec<u32> = Vec::new();
    let process_arg: WideCString = WideCString::from_str(&".exe").unwrap();

    match process_arg.to_string().unwrap().parse::<u32>() {
        Ok(n) => {
            process_ids.push(n);
        },
        Err(_) => {
            process_ids = process_module::get_process_ids_from_name(&process_arg);
            if process_ids.is_empty() {
                println!("Process with name {} does not exist.", process_arg.to_string().unwrap());
                return false;
            }
        }
    }

   for sf_pid in process_ids {
        let process_handle: HANDLE = process_module::open_process(
            sf_pid,
            winapi::um::winnt::PROCESS_CREATE_THREAD
                        | winapi::um::winnt::PROCESS_QUERY_INFORMATION
                        | winapi::um::winnt::PROCESS_VM_OPERATION
                         | winapi::um::winnt::PROCESS_VM_WRITE
                         | winapi::um::winnt::PROCESS_VM_READ
            );

        if process_handle == null_mut() || process_handle.is_null() {
            println!("Process with id {:?} does not exist or is not accessible.", sf_pid);
            return false;
        }

        let remote_module: winapi::shared::minwindef::HMODULE = process_module::find_remote_module_by_path(sf_pid, dll_path_real);

        if remote_module != null_mut() {
            println!("DLL already exists in process. HMODULE: {:?}.", remote_module);
            println!("Injection failed.");

            return false;
        } else {
            if inject::inject_library(process_handle, &dll_path_real) {
                println!("Successfully injected {:?} into {:?}.", dll_path, sf_pid);
            } else {
                println!("Injection failed.");
                return false;
            }
        }

        if process_handle != null_mut() {
            unsafe { CloseHandle( process_handle ); }
        }
    }

    return true;
   
}

fn initialize_handlers() {
    ctrlc::set_handler(move || {
        println!("received Ctrl+C!");
        std::process::exit(1);
    }).expect("Error setting Ctrl-C handler");
}

fn spawn_sf( args: Vec<String>, sf_spawned : &mut bool) -> Option<process::Child> {
    let hklm = RegKey::predef(HKEY_CURRENT_USER);
    let cur_ver = hklm.open_subkey("SOFTWARE\\SFR\\").expect("Failed to open subkey");

    let path : String = cur_ver.get_value("InstallPath").expect("Failed to read product name");

    let path_str = path;

    *sf_spawned = is_sf_loaded();

    if !*sf_spawned {
        let sf_child : Option<process::Child> = Some(process::Command::new(path_str + "\\.exe")
        // .current_dir(path_str)
            .args(&[&args[1]])

            .spawn()
            .expect("ls command failed to start"));

        println!("SF Spawned");

        return sf_child;
    } else {
        println!("Already spawned");
    }

    return None;
}

fn duplicate<T>(x: T) -> T { x } // sic

#[async_std::main]
async fn main() {
    //hide_console_window();

    unsafe { SetEnvironmentVariableA(CString::new("__COMPAT_LAYER").unwrap().as_ptr(), CString::new("RunAsInvoker").unwrap().as_ptr()) };

    initialize_handlers();

    let mut sf_spawned : bool = false;
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        println!("Invalid amount of arguments");
        process::exit(1);
    }

    let mut sf_child : Option<process::Child>;

    // Monitor to check (initial check)
    monitor::monitor_processes(&mut sf_spawned);

    sf_child = spawn_sf(args, &mut sf_spawned);

    let mut count = 0;

	// Try 4 times
	while count != 4 || !sf_spawned {
        sf_spawned = is_sf_loaded();
		count = count + 1
    }
    
    sf_spawned = is_sf_loaded();

    if !sf_spawned {
        process::exit(4);
    } else {
        let os_string = OsString::from(".dll");

        if !inject_dll(os_string) {
            process::exit(100);
        }
    }

    let sf_pid :u32 = sf_child.take().unwrap().id();

    // Get the initial modules
    let mut init_modules: Vec<process_module::ModuleResult> = Vec::new();
    let mut game_mods_loaded = false;
    let mut initialized_modules = false;

    // let handle = task::spawn(async move {
    //     loop {
    //         let mods = process_module::get_modules(sf_pid);
    //         if mods.len() == 120 {
    //             println!("Modules initialized");
    //             let myref = &mut game_mods_loaded;
    //             *myref = true;
    //             break;
    //         }
    //     }
    // });

    let timer = timer::Timer::new();
    let count = Arc::new(Mutex::new(0));
    let _guard = {
        let count = count.clone();
        timer.schedule_repeating(chrono::Duration::seconds(5), move || {
            let mut safe;
            //println!("Timer {:?}", game_mods_loaded );
            safe = monitor::monitor_processes(&mut sf_spawned);

            if !safe {           
                    // // Send Report
                if sf_child.is_some() {
                    sf_child.take().unwrap().kill().expect("!kill");
                }
                process::exit(2);
            }

            match monitor::detect_logitech_scripts() {
                Ok(v) => {
                    // Send Report
                        if v {
                            if sf_child.is_some() {
                                sf_child.take().unwrap().kill().expect("!kill");
                            }
                            process::exit(5);
                        }
                    },
                Err(e) => println!("error parsing header: {:?}", e),
            };

            if game_mods_loaded {
                if !initialized_modules {
                    init_modules= process_module::get_modules(sf_pid);
                    initialized_modules = true;
                }

                safe = monitor::dll_inject_checker(&mut init_modules, sf_pid);
                if !safe {
                    println!("LOL BYE MATE" );
                        // // Send Report
                    if sf_child.is_some() {
                        sf_child.take().unwrap().kill().expect("!kill");
                    }
                    process::exit(2);
                }
            } else {
                let mods = process_module::get_modules(sf_pid);
                if mods.len() == 120 {
                    println!("Modules initialized");
                    game_mods_loaded = true;
                }    
            }
            *count.lock().unwrap() += 1;
        })
    };

    loop { }
}
