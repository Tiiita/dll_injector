use std::{
    ffi::{CStr, CString},
    mem::zeroed,
    ptr,
};

use winapi::{shared::minwindef::LPVOID, um::{
    handleapi::CloseHandle, libloaderapi::{GetModuleHandleA, GetProcAddress}, memoryapi::{VirtualAllocEx, WriteProcessMemory}, processthreadsapi::{CreateRemoteThread, OpenProcess}, synchapi::WaitForSingleObject, tlhelp32::{
        CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
    }, winnt::{
        MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PROCESS_ALL_ACCESS,
    }
}};

fn main() {
    let process = unsafe { process_by_name("explorer.exe") };

    if process.is_none() {
        return;
    }

    let pid = process.unwrap().th32ProcessID;
    let dll_path = "";

    unsafe {
        inject_dll(pid, dll_path);
    }
}

unsafe fn inject_dll(pid: u32, dll_path: &str) {
    let h_process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);

    let dll_path_cstr = CString::new(dll_path).expect("CString::new failed");
    let dll_path_len = dll_path_cstr.as_bytes_with_nul().len();
    let alloc_mem = VirtualAllocEx(
        h_process,
        ptr::null_mut(),
        dll_path_len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );

    WriteProcessMemory(
        h_process,
        alloc_mem,
        dll_path_cstr.as_ptr() as LPVOID,
        dll_path_len,
        ptr::null_mut(),
    );


    let kernel32_handle = GetModuleHandleA(b"kernel32.dll\0".as_ptr() as *const i8);
    let load_library = GetProcAddress(
        kernel32_handle,
        b"LoadLibraryA\0".as_ptr() as *const i8,
    );
    
    let mut thread_id = 0;
    let h_thread = CreateRemoteThread(
        h_process,
        ptr::null_mut(),
        0,
        Some(std::mem::transmute::<_, unsafe extern "system" fn(LPVOID) -> u32>(
            load_library as *const ())),
        alloc_mem,
        0,
        &mut thread_id,
    );

    WaitForSingleObject(h_thread, 0xFFFFFFFF);

    CloseHandle(h_thread);
    CloseHandle(h_process);
}

unsafe fn process_by_name(name: &str) -> Option<PROCESSENTRY32> {
    let h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    let mut pe32: PROCESSENTRY32 = zeroed();
    pe32.dwSize = size_of::<PROCESSENTRY32>() as u32;

    if Process32First(h_snapshot, &mut pe32) == 0 {
        return None;
    }

    loop {
        let current_p_name = CStr::from_ptr(pe32.szExeFile.as_ptr())
            .to_string_lossy()
            .to_string();

        if current_p_name == name {
            return Some(pe32);
        }

        if Process32Next(h_snapshot, &mut pe32) == 0 {
            return None;
        }
    }
}
