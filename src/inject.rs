use std::io::Error;

use std::path::Path;
use std::ptr::null_mut;
use winapi::um::winnt::HANDLE;
use std::ffi::{CString, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::{mem};

use winapi::um::processthreadsapi::{
    CreateRemoteThread
};

use winapi::um::synchapi::{ 
    WaitForSingleObject
};

use winapi::um::memoryapi::{
    VirtualAllocEx,
    WriteProcessMemory,
    VirtualFreeEx
};

use winapi::um::libloaderapi::{
    GetProcAddress,
    LoadLibraryW
};

use winapi::um::handleapi::{
    CloseHandle
};

fn to_wstring(s: &str) -> Vec<u16> {
    let v: Vec<u16> = OsStr::new(s).encode_wide().chain(Some(0).into_iter()).collect();
    v
}

pub fn inject_library(process_handle: HANDLE, dll_path: &Path) -> bool {
    if process_handle == null_mut() || process_handle.is_null() {
        println!("Process does not exist or is not accessible.");
        return false;
    }

    if !dll_path.exists() {
        println!("DLL does not exist");
        return false;
    }

   // let kernel32_module: winapi::shared::minwindef::HMODULE;
    // unsafe {
    //     kernel32_module = GetModuleHandleA(CString::new("kernel32.dll").unwrap().as_ptr());
    // }

    // if kernel32_module == null_mut() || kernel32_module.is_null() {
    //     println!("Failed to find {:?}.", kernel32_str);
    //     return false;
    // }
        // CString::new("LoadLibraryW").unwrap().as_ptr()

    let load_library_address : winapi::shared::minwindef::FARPROC;
    let kernel32_module : winapi::shared::minwindef::HMODULE;

    unsafe {
     //   kernel32_module = GetModuleHandleA(CString::new("kernel32.dll").unwrap().as_ptr());
        kernel32_module = LoadLibraryW(to_wstring("kernel32.dll").as_ptr());
        load_library_address = GetProcAddress(kernel32_module, CString::new("LoadLibraryA").unwrap().as_ptr());
    }

    if load_library_address == null_mut() || load_library_address.is_null() {
        println!("Failed to find kernel @ {:?} and loadlibraryA @ {:?}", kernel32_module, load_library_address);
        return false;
    }

    println!("Found kernel @ {:?} and loadlibraryA @ {:?}", kernel32_module, load_library_address);

    let dll = ".dll";

    let full_path = dll;
    let dll_path_size = full_path.len() as usize + 1;

  //  let dll_path_str = dll_path.as_os_str();
 //   let dll_path_size: usize = ((dll_path_str.len() + 1) * mem::size_of::<u16>()) as usize;
    println!("DLL Path size {:?}", dll_path_size);

    let dll_name_addr : *mut winapi::ctypes::c_void;

    // Write the dll name 
    unsafe {
        dll_name_addr = VirtualAllocEx(process_handle, null_mut(), dll_path_size, 
               winapi::um::winnt::MEM_COMMIT | winapi::um::winnt::MEM_RESERVE , winapi::um::winnt::PAGE_EXECUTE_READWRITE);
    }

    if dll_name_addr == null_mut() || dll_name_addr.is_null() {
        println!("Failed to allocate memory in the target process.");
        return false;
    }

    let mut bytes_written: winapi::shared::basetsd::SIZE_T = 0;
    let bytes_written_ptr: *mut winapi::shared::basetsd::SIZE_T = &mut bytes_written as *mut _ as *mut winapi::shared::basetsd::SIZE_T;
    let wpm_ret: winapi::shared::minwindef::BOOL;

    //  dll_path_str.encode_wide().collect::<Vec<_>>().as_ptr() as *const winapi::ctypes::c_void
    unsafe {
        wpm_ret = WriteProcessMemory(process_handle, dll_name_addr,  CString::new(full_path).unwrap().as_ptr() as *const std::os::raw::c_void
           , dll_path_size, bytes_written_ptr);
    }

    println!("Expected = {:?}. DLL str = {}", dll_path_size, dll);
    println!("Wrote = {:?}", bytes_written);
    
    if wpm_ret == winapi::shared::minwindef::FALSE || bytes_written < dll_path_size {
        println!("Failed to write memory to the target process.");
        unsafe {
            VirtualFreeEx(process_handle, dll_name_addr, dll_path_size, winapi::um::winnt::MEM_RELEASE);
        }
        return false;
    }

    let thread_handle: HANDLE;
    unsafe {
        thread_handle = CreateRemoteThread(process_handle, null_mut(), 0, Some(mem::transmute(load_library_address)), dll_name_addr, 0, null_mut());
    }
    println!("spawned remote thread @ {:?}", thread_handle);
    let e = Error::last_os_error();
    println!("windows error: {:?}", e);

    if thread_handle == null_mut() || thread_handle.is_null() {
        println!("Failed to inject the dll.");
        unsafe {
            VirtualFreeEx(process_handle, dll_name_addr, 0, winapi::um::winnt::MEM_RELEASE);
        }
        return false;
    }

    unsafe {
        println!("Started Waiting for thread");
        WaitForSingleObject(thread_handle, winapi::um::winbase::INFINITE);
        println!("Done waiting");
        let e = Error::last_os_error();
        println!("windows error: {:?}", e);

        CloseHandle(thread_handle);

        // dll_path_size
        VirtualFreeEx(process_handle, dll_name_addr, 0, winapi::um::winnt::MEM_RELEASE);
    }
    return true;
}
