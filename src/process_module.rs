use widestring::WideCString;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

use std::ptr::null_mut;
use std::path::Path;
use std::{mem};

use winapi::um::winnt::HANDLE;

use winapi::um::tlhelp32::{ 
    CreateToolhelp32Snapshot,
    Module32FirstW,
    Module32NextW,
    Process32FirstW,
    Process32NextW
};

use winapi::um::processthreadsapi::{
    OpenProcess
};

use winapi::um::handleapi::{
    CloseHandle
};

pub struct ModuleResult {
    pub exe_path: WideCString,
    pub module_name: WideCString,
}

pub fn get_modules(process_id: u32) -> Vec<ModuleResult> {
    let mut vec = Vec::new();

    let snapshot: HANDLE;
    let mut module_entry = winapi::um::tlhelp32::MODULEENTRY32W {
        dwSize: mem::size_of::<winapi::um::tlhelp32::MODULEENTRY32W>() as u32,
        th32ModuleID: 0,
        th32ProcessID: 0,
        GlblcntUsage: 0,
        ProccntUsage: 0,
        modBaseAddr: null_mut(),
        modBaseSize: 0,
        hModule: null_mut(),
        szModule: [0; winapi::um::tlhelp32::MAX_MODULE_NAME32 + 1],
        szExePath: [0; winapi::shared::minwindef::MAX_PATH]
    };

    unsafe { snapshot = CreateToolhelp32Snapshot(winapi::um::tlhelp32::TH32CS_SNAPMODULE, process_id); }

    unsafe {
             if Module32FirstW(snapshot, &mut module_entry) == winapi::shared::minwindef::TRUE {

                while Module32NextW(snapshot, &mut module_entry) == winapi::shared::minwindef::TRUE {
                    let wstr_path:OsString = OsStringExt::from_wide(&module_entry.szExePath);
                    let exe_path_str:WideCString = WideCString::from_str_with_nul(wstr_path).unwrap();

                    let wide_str:OsString = OsStringExt::from_wide(&module_entry.szModule);
                    let exe_str:WideCString = WideCString::from_str_with_nul(wide_str).unwrap();
                    vec.push(ModuleResult{ exe_path: exe_path_str, module_name: exe_str });
                }
	       }
    }

	if snapshot != winapi::um::handleapi::INVALID_HANDLE_VALUE {
		unsafe { CloseHandle( snapshot ); }
    }

	return vec;
}

pub fn open_process(process_id: u32, desired_access: winapi::shared::minwindef::DWORD) -> HANDLE {
    let process_handle: HANDLE;
    unsafe {
        process_handle = OpenProcess(desired_access, winapi::shared::minwindef::FALSE, process_id);
    }

    return process_handle;
}

pub fn find_remote_module_by_path(process_id: u32, dll_path: &Path) -> winapi::shared::minwindef::HMODULE {
    let snapshot: HANDLE;
    let mut module_entry = winapi::um::tlhelp32::MODULEENTRY32W {
        dwSize: mem::size_of::<winapi::um::tlhelp32::MODULEENTRY32W>() as u32,
        th32ModuleID: 0,
        th32ProcessID: 0,
        GlblcntUsage: 0,
        ProccntUsage: 0,
        modBaseAddr: null_mut(),
        modBaseSize: 0,
        hModule: null_mut(),
        szModule: [0; winapi::um::tlhelp32::MAX_MODULE_NAME32 + 1],
        szExePath: [0; winapi::shared::minwindef::MAX_PATH]
    };

    unsafe { snapshot = CreateToolhelp32Snapshot(winapi::um::tlhelp32::TH32CS_SNAPMODULE, process_id); }

    let mut module_handle: winapi::shared::minwindef::HMODULE = null_mut();
    unsafe {
             if Module32FirstW(snapshot, &mut module_entry) == winapi::shared::minwindef::TRUE {

                while Module32NextW(snapshot, &mut module_entry) == winapi::shared::minwindef::TRUE {
                    let wide_str:OsString = OsStringExt::from_wide(&module_entry.szExePath);
                    let exe_str:WideCString = WideCString::from_str_with_nul(wide_str).unwrap();
                    if exe_str.to_os_string() == dll_path.as_os_str() {
                        module_handle = module_entry.hModule;
                        break;
                    }
                }
	       }
    }

	if snapshot != winapi::um::handleapi::INVALID_HANDLE_VALUE {
		unsafe { CloseHandle( snapshot ); }
    }

	return module_handle;
}


pub fn get_process_ids_from_name(process_name: &WideCString) -> Vec<u32> {

    let snapshot: HANDLE;
    let mut process_entry = winapi::um::tlhelp32::PROCESSENTRY32W {
        dwSize: mem::size_of::<winapi::um::tlhelp32::PROCESSENTRY32W>() as u32,
        cntUsage: 0,
        th32ProcessID: 0,
        th32DefaultHeapID: 0,
        th32ModuleID: 0,
        cntThreads: 0,
        th32ParentProcessID: 0,
        pcPriClassBase: 0,
        dwFlags: 0,
        szExeFile: [0; winapi::shared::minwindef::MAX_PATH]
    };

    unsafe { snapshot = CreateToolhelp32Snapshot(winapi::um::tlhelp32::TH32CS_SNAPPROCESS, 0); }

    let mut process_ids: Vec<u32> = Vec::new();

    unsafe {
             if Process32FirstW(snapshot, &mut process_entry) == winapi::shared::minwindef::TRUE {
                while Process32NextW(snapshot, &mut process_entry) == winapi::shared::minwindef::TRUE {
                    let wide_str:OsString = OsStringExt::from_wide(&process_entry.szExeFile);
                    let exe_str:WideCString = WideCString::from_str_with_nul(wide_str).unwrap();
                    if exe_str == *process_name {
                        process_ids.push(process_entry.th32ProcessID);
                    }
                }
	       }
    }

	if snapshot != winapi::um::handleapi::INVALID_HANDLE_VALUE {
		unsafe { CloseHandle( snapshot ); }
    }

	return process_ids;
}