/// Windows WeChat 进程内存密钥扫描器
///
/// 使用 Windows API：
/// - CreateToolhelp32Snapshot + Process32Next: 枚举进程找 Weixin.exe
/// - OpenProcess: 获取进程句柄（需要 PROCESS_VM_READ | PROCESS_QUERY_INFORMATION）
/// - VirtualQueryEx: 枚举内存区域
/// - ReadProcessMemory: 读取内存内容
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::Path;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

use super::{
    collect_db_salts, collect_salt_adjacent_keys, decode_salt_hex, is_critical_missing_db,
    is_writable_readable_page, list_missing_encrypted_dbs, match_raw_keys, merge_key_entries,
    scan_key_patterns, KeyEntry, MAX_PATTERN_BYTES,
};

const CHUNK_SIZE: usize = 2 * 1024 * 1024;

/// 重扫间隔（hook_seconds 生效时）
const RESCAN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Windows 扫描入口。
///
/// `hook_seconds == 0` 时保持单次扫描；> 0 时在时间预算内循环
/// 「扫描 → 匹配 → 若关键库仍缺密钥则 sleep 后重扫」（等效 macOS 的 hook 等待窗口），
/// 直到关键库配齐或预算耗尽。`known` 为已有仍有效的密钥，并入结果避免误判缺失。
pub fn scan_keys_with_options(
    db_dir: &Path,
    hook_seconds: u64,
    known: &[KeyEntry],
) -> Result<Vec<KeyEntry>> {
    let start = std::time::Instant::now();
    let budget = std::time::Duration::from_secs(hook_seconds);
    let mut merged = known.to_vec();
    let mut attempt = 0u32;

    loop {
        attempt += 1;
        let scanned = scan_keys(db_dir)?;
        merged = merge_key_entries(&scanned, &merged);

        let total = collect_db_salts(db_dir).len();
        let missing_critical: Vec<String> = list_missing_encrypted_dbs(db_dir, &merged)
            .into_iter()
            .filter(|m| is_critical_missing_db(&m.rel))
            .map(|m| m.rel)
            .collect();
        eprintln!(
            "第 {} 次尝试：已配齐 {}/{} 个数据库密钥，关键库仍缺 {} 个",
            attempt,
            merged.len(),
            total,
            missing_critical.len()
        );

        if missing_critical.is_empty() || hook_seconds == 0 {
            return Ok(merged);
        }
        let elapsed = start.elapsed();
        if elapsed >= budget {
            eprintln!(
                "重扫预算 {}s 已耗尽，仍缺关键库：{}",
                hook_seconds,
                missing_critical.join(", ")
            );
            return Ok(merged);
        }
        let remain = budget - elapsed;
        let sleep = remain.min(RESCAN_INTERVAL);
        eprintln!(
            "等待 {}s 后重扫（剩余预算 {}s）；请在微信中打开/滚动相关聊天，触发密钥加载到内存",
            sleep.as_secs(),
            remain.as_secs()
        );
        std::thread::sleep(sleep);
    }
}

/// 查找 Weixin.exe 主进程 PID。
///
/// 微信是多进程架构（主进程 + 渲染/插件子进程同名 Weixin.exe），
/// 密钥材料在主进程堆中，故枚举所有同名进程并取工作集最大者。
pub(crate) fn find_wechat_pid() -> Option<u32> {
    // SAFETY: CreateToolhelp32Snapshot 标准 Windows API
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()? };

    let mut entry = PROCESSENTRY32 {
        dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
        ..Default::default()
    };

    let mut best: Option<(u32, usize)> = None; // (pid, working_set_bytes)
    let mut count = 0u32;
    // SAFETY: Process32First/Process32Next 标准快照遍历
    unsafe {
        if Process32First(snap, &mut entry).is_err() {
            let _ = CloseHandle(snap);
            return None;
        }
        loop {
            let name =
                std::ffi::CStr::from_ptr(entry.szExeFile.as_ptr() as *const i8).to_string_lossy();
            if name.eq_ignore_ascii_case("Weixin.exe") {
                count += 1;
                let pid = entry.th32ProcessID;
                let ws = working_set_size(pid).unwrap_or(0);
                if best.map_or(true, |(_, cur)| ws > cur) {
                    best = Some((pid, ws));
                }
            }
            if Process32Next(snap, &mut entry).is_err() {
                break;
            }
        }
        let _ = CloseHandle(snap);
    }

    if count > 1 {
        if let Some((pid, ws)) = best {
            eprintln!(
                "发现 {} 个 Weixin.exe 进程，选择工作集最大的主进程 PID {}（约 {} MB）",
                count,
                pid,
                ws / (1024 * 1024)
            );
        }
    }
    best.map(|(pid, _)| pid)
}

/// 读取指定进程的工作集大小（字节）；无权打开时返回 None
fn working_set_size(pid: u32) -> Option<usize> {
    use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    // SAFETY: OpenProcess 仅需查询权限
    let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false, pid).ok()? };
    let mut pmc = PROCESS_MEMORY_COUNTERS {
        cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        ..Default::default()
    };
    let cb = pmc.cb;
    // SAFETY: pmc 指向有效缓冲区，cb 已按 API 要求填结构大小
    let ok = unsafe { GetProcessMemoryInfo(handle, &mut pmc, cb) };
    unsafe {
        let _ = CloseHandle(handle);
    }
    ok.ok().map(|_| pmc.WorkingSetSize)
}

pub fn scan_keys(db_dir: &Path) -> Result<Vec<KeyEntry>> {
    let pid = find_wechat_pid().context("找不到 Weixin.exe 进程，请确认微信正在运行")?;
    eprintln!("WeChat PID: {}", pid);

    // SAFETY: OpenProcess 请求读取权限
    let process = unsafe {
        OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid)
            .context("OpenProcess 失败，请以管理员权限运行")?
    };

    let db_salts = collect_db_salts(db_dir);
    eprintln!("找到 {} 个加密数据库", db_salts.len());

    let salt_bytes: Vec<[u8; 16]> = db_salts
        .iter()
        .filter_map(|(s, _)| decode_salt_hex(s))
        .collect();

    eprintln!("扫描进程内存...");
    let (mut raw_keys, extra_keys) = scan_memory(process, &salt_bytes)?;
    eprintln!(
        "找到 {} 个候选密钥（x'hex' 模式 {} 个，salt 邻接二进制 {} 个）",
        raw_keys.len() + extra_keys.len(),
        raw_keys.len(),
        extra_keys.len()
    );

    // SAFETY: 关闭进程句柄
    unsafe {
        let _ = CloseHandle(process);
    }

    // 纯 key 以 (key, "") 形式并入候选；match_raw_keys 内部会对全部 DB salt 尝试
    for k in extra_keys {
        raw_keys.push((k, String::new()));
    }

    let entries = match_raw_keys(db_dir, &raw_keys, &db_salts);
    eprintln!(
        "匹配到 {}/{} 个数据库密钥（来自 {} 个候选 key）",
        entries.len(),
        db_salts.len(),
        raw_keys.len()
    );
    Ok(entries)
}

fn scan_memory(
    process: HANDLE,
    salts: &[[u8; 16]],
) -> Result<(Vec<(String, String)>, Vec<String>)> {
    let mut results: Vec<(String, String)> = Vec::new();
    let mut extra_keys: Vec<String> = Vec::new();
    // seen 集合跨 chunk 复用，避免 salt 邻接结果重复
    let mut seen_extra: HashSet<String> = HashSet::new();
    let mut addr: usize = 0;

    loop {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        // SAFETY: VirtualQueryEx 枚举进程内存区域
        let ret = unsafe {
            VirtualQueryEx(
                process,
                Some(addr as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if ret == 0 {
            break;
        }

        let region_size = mbi.RegionSize;
        let base = mbi.BaseAddress as usize;

        // 只扫描已提交的可读可写页面（含 WRITECOPY / EXECUTE_*WRITE*；见
        // `is_writable_readable_page`，从 old-main #54 捞回）。
        if mbi.State == MEM_COMMIT && is_writable_readable_page(mbi.Protect.0) {
            scan_region(
                process,
                base,
                region_size,
                salts,
                &mut results,
                &mut extra_keys,
                &mut seen_extra,
            );
        }

        addr = base.saturating_add(region_size);
        if addr == 0 {
            break; // overflow
        }
    }

    Ok((results, extra_keys))
}

#[allow(clippy::too_many_arguments)]
fn scan_region(
    process: HANDLE,
    base: usize,
    size: usize,
    salts: &[[u8; 16]],
    results: &mut Vec<(String, String)>,
    extra_keys: &mut Vec<String>,
    seen_extra: &mut HashSet<String>,
) {
    let overlap = MAX_PATTERN_BYTES;
    let mut offset = 0usize;

    loop {
        if offset >= size {
            break;
        }
        let chunk_size = std::cmp::min(CHUNK_SIZE, size - offset);
        let addr = base + offset;
        let mut buf = vec![0u8; chunk_size];
        let mut bytes_read: usize = 0;

        // SAFETY: ReadProcessMemory 读取目标进程内存
        let ok = unsafe {
            ReadProcessMemory(
                process,
                addr as *const _,
                buf.as_mut_ptr() as *mut _,
                chunk_size,
                Some(&mut bytes_read),
            )
            .is_ok()
        };

        if ok && bytes_read > 0 {
            buf.truncate(bytes_read);
            search_pattern(&buf, results, salts, extra_keys, seen_extra);
        }

        if chunk_size > overlap {
            offset += chunk_size - overlap;
        } else {
            offset += chunk_size;
        }
    }
}

/// 搜索单块内存：`x'<key><salt>'` 字符串模式 + salt 邻接二进制 key
fn search_pattern(
    buf: &[u8],
    results: &mut Vec<(String, String)>,
    salts: &[[u8; 16]],
    extra_keys: &mut Vec<String>,
    seen_extra: &mut HashSet<String>,
) {
    scan_key_patterns(buf, results);
    collect_salt_adjacent_keys(buf, salts, extra_keys, seen_extra);
}
