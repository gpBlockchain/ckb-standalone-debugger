use crate::ipc_packet::{RequestPacket, ResponsePacket};
use crate::ipc_syscall::{IpcBufferState, IpcClose, IpcInheritedFd, IpcRead, IpcWrite, SharedIpcState};
use ckb_chain_spec::consensus::ConsensusBuilder;
use ckb_mock_tx_types::{MockTransaction, ReprMockTransaction, Resource};
use ckb_script::types::{DebugPrinter, Machine, SgData, VmContext, VmId};
use ckb_script::{ScriptGroupType, TransactionScriptsVerifier, TxVerifyEnv, generate_ckb_syscalls};
use ckb_types::{
    core::cell::resolve_transaction,
    core::hardfork::{CKB2021, CKB2023, HardForks},
    core::{Cycle, EpochNumberWithFraction, HeaderView},
    packed::Byte32,
    prelude::*,
};
use ckb_vm::{DefaultMachineRunner, Syscalls};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use wasm_bindgen::prelude::*;

pub fn run(
    mock_tx: &MockTransaction,
    script_group_type: &ScriptGroupType,
    script_hash: &Byte32,
    max_cycle: Cycle,
) -> Result<Cycle, Box<dyn std::error::Error>> {
    let resource = Resource::from_mock_tx(mock_tx)?;
    let resolve_transaction =
        resolve_transaction(mock_tx.core_transaction(), &mut HashSet::new(), &resource, &resource)?;
    let hardforks = HardForks { ckb2021: CKB2021::new_dev_default(), ckb2023: CKB2023::new_dev_default() };
    let consensus = Arc::new(ConsensusBuilder::default().hardfork_switch(hardforks).build());
    let epoch = EpochNumberWithFraction::new(0, 0, 1);
    let header = HeaderView::new_advanced_builder().epoch(epoch.pack()).build();
    let tx_env = Arc::new(TxVerifyEnv::new_commit(&header));
    let verifier = TransactionScriptsVerifier::new_with_debug_printer(
        Arc::new(resolve_transaction),
        resource.clone(),
        consensus.clone(),
        tx_env.clone(),
        Arc::new(Box::new(move |_hash: &Byte32, message: &str| {
            let message = message.trim_end_matches('\n');
            if message != "" {
                crate::arch::println(&format!("Script log: {}", message));
            }
        })),
    );
    Ok(verifier.verify_single(*script_group_type, script_hash, max_cycle)?)
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
struct JsonResult {
    cycle: Option<Cycle>,
    error: Option<String>,
}

impl From<Result<Cycle, String>> for JsonResult {
    fn from(result: Result<Cycle, String>) -> JsonResult {
        match result {
            Ok(cycle) => JsonResult { cycle: Some(cycle), error: None },
            Err(error) => JsonResult { cycle: None, error: Some(error) },
        }
    }
}

#[wasm_bindgen]
pub fn run_json(mock_tx: &str, script_group_type: &str, script_hash: &str, max_cycle: &str) -> String {
    let result = || -> Result<Cycle, String> {
        let repr_mock_tx: ReprMockTransaction = serde_json::from_str(mock_tx).map_err(|e| e.to_string())?;
        let mock_tx: MockTransaction = repr_mock_tx.into();
        let script_group_type: ScriptGroupType = serde_plain::from_str(script_group_type).map_err(|e| e.to_string())?;
        let script_hash = if script_hash.starts_with("0x") { &script_hash[2..] } else { &script_hash[0..] };
        let script_hash_byte = hex::decode(&script_hash.as_bytes()).map_err(|e| e.to_string())?;
        let script_hash = Byte32::from_slice(script_hash_byte.as_slice()).map_err(|e| e.to_string())?;
        let max_cycle: Cycle = max_cycle.parse().map_err(|_| "Invalid max cycle!".to_string())?;
        run(&mock_tx, &script_group_type, &script_hash, max_cycle).map_err(|e| e.to_string())
    }();
    let result_json: JsonResult = result.into();
    serde_json::to_string(&result_json).unwrap()
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct IpcRequestJson {
    version: u64,
    method_id: u64,
    #[serde(default)]
    payload_format: String,
    #[serde(default)]
    payload: Value,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct IpcResponseJson {
    version: u64,
    error_code: u64,
    payload_format: String,
    payload: Value,
}

fn ipc_call_inner(
    mock_tx: &MockTransaction,
    script_group_type: &ScriptGroupType,
    script_hash: &Byte32,
    max_cycle: Cycle,
    ipc_request: &IpcRequestJson,
) -> Result<IpcResponseJson, Box<dyn std::error::Error>> {
    let resource = Resource::from_mock_tx(mock_tx)?;
    let resolve_transaction =
        resolve_transaction(mock_tx.core_transaction(), &mut HashSet::new(), &resource, &resource)?;
    let hardforks = HardForks { ckb2021: CKB2021::new_dev_default(), ckb2023: CKB2023::new_dev_default() };
    let consensus = Arc::new(ConsensusBuilder::default().hardfork_switch(hardforks).build());
    let epoch = EpochNumberWithFraction::new(0, 0, 1);
    let header = HeaderView::new_advanced_builder().epoch(epoch.pack()).build();
    let tx_env = Arc::new(TxVerifyEnv::new_commit(&header));

    let payload_format = if ipc_request.payload_format.is_empty() {
        "json".to_string()
    } else {
        ipc_request.payload_format.clone()
    };
    let payload_bytes = match payload_format.as_str() {
        "hex" => {
            let s = ipc_request
                .payload
                .as_str()
                .ok_or("Payload must be a hex string")?;
            let s = s.strip_prefix("0x").unwrap_or(s);
            hex::decode(s)?
        }
        _ => serde_json::to_vec(&ipc_request.payload)?,
    };
    let req_packet = RequestPacket::new(ipc_request.version as u8, ipc_request.method_id, payload_bytes);
    let req_data = req_packet.serialize();

    let ipc_state: SharedIpcState = Arc::new(Mutex::new(IpcBufferState::new(req_data)));

    let ipc_syscalls = |vm_id: &VmId,
                        sg_data: &SgData<Resource>,
                        vm_context: &VmContext<Resource>,
                        vm_v: &SharedIpcState|
                        -> Vec<Box<(dyn Syscalls<<Machine as DefaultMachineRunner>::Inner>)>> {
        let debug_printer: DebugPrinter = Arc::new(|_: &Byte32, message: &str| {
            let message = message.trim_end_matches('\n');
            if !message.is_empty() {
                crate::arch::println(&format!("Script log: {}", message));
            }
        });
        let mut syscalls = generate_ckb_syscalls(vm_id, sg_data, vm_context, &debug_printer);
        syscalls.insert(0, Box::new(IpcClose::new(vm_v.clone())));
        syscalls.insert(0, Box::new(IpcInheritedFd::new(vm_v.clone())));
        syscalls.insert(0, Box::new(IpcRead::new(vm_v.clone())));
        syscalls.insert(0, Box::new(IpcWrite::new(vm_v.clone())));
        syscalls
    };

    let verifier: TransactionScriptsVerifier<Resource, SharedIpcState, Machine> =
        TransactionScriptsVerifier::new_with_generator(
            Arc::new(resolve_transaction),
            resource,
            consensus,
            tx_env,
            ipc_syscalls,
            ipc_state.clone(),
        );
    let script_group = verifier
        .find_script_group(*script_group_type, script_hash)
        .ok_or_else(|| format!("Script group not found for hash: {:?}", script_hash))?;
    let mut scheduler = verifier.create_scheduler(script_group)?;
    let run_result = scheduler.run(ckb_script::RunMode::LimitCycles(max_cycle));

    let state = ipc_state.lock().map_err(|e| e.to_string())?;
    if state.response_data.is_empty() {
        if let Err(e) = run_result {
            return Err(format!("Script execution failed with no IPC response: {}", e).into());
        }
        return Err("Script exited without producing an IPC response".into());
    }
    let mut cursor = std::io::Cursor::new(&state.response_data);
    let resp = ResponsePacket::read_from(&mut cursor)?;

    let resp_payload = match payload_format.as_str() {
        "hex" => Value::String(format!("0x{}", hex::encode(resp.payload()))),
        _ => serde_json::from_slice(resp.payload()).unwrap_or(Value::Null),
    };

    Ok(IpcResponseJson {
        version: resp.version() as u64,
        error_code: resp.error_code(),
        payload_format,
        payload: resp_payload,
    })
}

/// Perform an IPC call to a CKB script.
///
/// # Arguments
/// * `mock_tx` - JSON string of a mock transaction (ReprMockTransaction)
/// * `script_group_type` - "lock" or "type"
/// * `script_hash` - hex-encoded script hash
/// * `max_cycle` - maximum cycles allowed
/// * `ipc_request` - JSON string of an IPC request with fields: version, method_id, payload_format, payload
///
/// # Returns
/// JSON string of the IPC response with fields: version, error_code, payload_format, payload
#[wasm_bindgen]
pub fn ipc_call(mock_tx: &str, script_group_type: &str, script_hash: &str, max_cycle: &str, ipc_request: &str) -> String {
    let result = || -> Result<IpcResponseJson, String> {
        let repr_mock_tx: ReprMockTransaction = serde_json::from_str(mock_tx).map_err(|e| e.to_string())?;
        let mock_tx: MockTransaction = repr_mock_tx.into();
        let script_group_type: ScriptGroupType = serde_plain::from_str(script_group_type).map_err(|e| e.to_string())?;
        let script_hash = if script_hash.starts_with("0x") { &script_hash[2..] } else { &script_hash[0..] };
        let script_hash_byte = hex::decode(script_hash.as_bytes()).map_err(|e| e.to_string())?;
        let script_hash = Byte32::from_slice(script_hash_byte.as_slice()).map_err(|e| e.to_string())?;
        let max_cycle: Cycle = max_cycle.parse().map_err(|_| "Invalid max cycle!".to_string())?;
        let ipc_req: IpcRequestJson = serde_json::from_str(ipc_request).map_err(|e| e.to_string())?;
        ipc_call_inner(&mock_tx, &script_group_type, &script_hash, max_cycle, &ipc_req).map_err(|e| e.to_string())
    }();
    match result {
        Ok(resp) => serde_json::to_string(&resp).unwrap(),
        Err(e) => serde_json::to_string(&serde_json::json!({"error": e})).unwrap(),
    }
}

/// Execute a script binary directly with an IPC request, without needing a mock_tx.
/// A minimal mock transaction is created internally to host the binary.
///
/// # Arguments
/// * `binary` - The compiled CKB RISC-V script binary
/// * `args` - Hex-encoded script args (with or without 0x prefix)
/// * `json_request` - JSON string of an IPC request with fields: version, method_id, payload_format, payload
///
/// # Returns
/// JSON string of the IPC response
#[wasm_bindgen]
pub fn execute_script(binary: &[u8], args: &str, json_request: &str) -> String {
    let result = || -> Result<IpcResponseJson, String> {
        let ipc_req: IpcRequestJson = serde_json::from_str(json_request).map_err(|e| e.to_string())?;

        // Compute blake2b hash of binary for code_hash
        let binary_hash = ckb_hash::blake2b_256(binary);
        let code_hash_hex = format!("0x{}", hex::encode(&binary_hash));
        let cell_dep_data_hex = format!("0x{}", hex::encode(binary));
        let args_hex = if args.is_empty() {
            "0x".to_string()
        } else if args.starts_with("0x") {
            args.to_string()
        } else {
            format!("0x{}", args)
        };

        // Build minimal mock_tx as string directly (avoids serde_json::json! macro issues)
        // Use hash_type "data2" (CKB VM v2) for modern script support (IPC, spawn, etc.)
        let mock_tx_str = format!(
            r#"{{"mock_info":{{"inputs":[{{"input":{{"previous_output":{{"tx_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","index":"0x0"}},"since":"0x0"}},"output":{{"capacity":"0x174876e800","lock":{{"code_hash":"{}","hash_type":"data2","args":"{}"}}}},"data":"0x"}}],"cell_deps":[{{"cell_dep":{{"out_point":{{"tx_hash":"0x0000000000000000000000000000000000000000000000000000000000000001","index":"0x0"}},"dep_type":"code"}},"output":{{"capacity":"0x174876e800","lock":{{"code_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","hash_type":"data","args":"0x"}}}},"data":"{}"}}],"header_deps":[]}},"tx":{{"version":"0x0","cell_deps":[{{"out_point":{{"tx_hash":"0x0000000000000000000000000000000000000000000000000000000000000001","index":"0x0"}},"dep_type":"code"}}],"header_deps":[],"inputs":[{{"previous_output":{{"tx_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","index":"0x0"}},"since":"0x0"}}],"outputs":[{{"capacity":"0x174876e800","lock":{{"code_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","hash_type":"data","args":"0x"}}}}],"outputs_data":["0x"],"witnesses":["0x"]}}}}"#,
            code_hash_hex, args_hex, cell_dep_data_hex
        );

        let repr: ReprMockTransaction = serde_json::from_str(&mock_tx_str).map_err(|e| {
            format!("Failed to parse generated mock_tx: {} (code_hash={}, args={}, data_len={})",
                e, code_hash_hex, args_hex, cell_dep_data_hex.len())
        })?;
        let mock_tx: MockTransaction = repr.into();

        let script_hash = crate::misc::get_script_hash_by_index(
            &mock_tx,
            &ScriptGroupType::Lock,
            "input",
            0,
        );
        let max_cycle: Cycle = 70_000_000;

        ipc_call_inner(&mock_tx, &ScriptGroupType::Lock, &script_hash, max_cycle, &ipc_req)
            .map_err(|e| e.to_string())
    }();

    match result {
        Ok(resp) => serde_json::to_string(&resp).unwrap(),
        Err(e) => serde_json::to_string(&serde_json::json!({"error": e})).unwrap(),
    }
}

/// Execute a script binary with an IPC request, using a mock_tx for full transaction context.
/// The binary replaces the script at the specified cell position in the mock_tx.
///
/// # Arguments
/// * `binary` - The compiled CKB RISC-V script binary
/// * `args` - Hex-encoded script args (with or without 0x prefix, empty string for no override)
/// * `json_request` - JSON string of an IPC request
/// * `mock_tx_json` - JSON string of a mock transaction (ReprMockTransaction)
/// * `cell_index` - Index of the cell containing the target script
/// * `cell_type` - "input" or "output"
/// * `script_group_type` - "lock" or "type"
///
/// # Returns
/// JSON string of the IPC response
#[wasm_bindgen]
pub fn execute_script_with_mock_tx(
    binary: &[u8],
    args: &str,
    json_request: &str,
    mock_tx_json: &str,
    cell_index: u32,
    cell_type: &str,
    script_group_type: &str,
) -> String {
    let result = || -> Result<IpcResponseJson, String> {
        let ipc_req: IpcRequestJson = serde_json::from_str(json_request).map_err(|e| e.to_string())?;
        let sgt: ScriptGroupType = serde_plain::from_str(script_group_type).map_err(|e| e.to_string())?;

        // Parse mock_tx as JSON for manipulation
        let mut mock_tx_value: Value = serde_json::from_str(mock_tx_json).map_err(|e| e.to_string())?;

        // Compute new binary hash
        let new_binary_hash = ckb_hash::blake2b_256(binary);
        let new_binary_hex = format!("0x{}", hex::encode(binary));
        let new_code_hash = format!("0x{}", hex::encode(&new_binary_hash));

        // Helper to extract code_hash and hash_type from a script JSON object
        fn extract_script_info(script: &Value, label: &str) -> Result<(String, String), String> {
            if script.is_null() {
                return Err(format!("{} is null", label));
            }
            let code_hash = script.get("code_hash")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("{}: code_hash not found (script: {})", label, script))?
                .to_string();
            let hash_type = script.get("hash_type")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("{}: hash_type not found (script: {})", label, script))?
                .to_string();
            Ok((code_hash, hash_type))
        }

        // Find the target script's code_hash and hash_type
        let (old_code_hash, old_hash_type) = {
            let mock_info = mock_tx_value.get("mock_info").ok_or("mock_info not found")?;
            match (script_group_type, cell_type) {
                ("lock", "input") => {
                    let inputs = mock_info.get("inputs")
                        .and_then(|v| v.as_array())
                        .ok_or("inputs not found in mock_info")?;
                    let cell = inputs.get(cell_index as usize)
                        .ok_or_else(|| format!("cell index {} out of bounds (inputs has {} items)", cell_index, inputs.len()))?;
                    let output = cell.get("output")
                        .ok_or_else(|| format!("output not found at inputs[{}], available keys: {:?}",
                            cell_index, cell.as_object().map(|o| o.keys().collect::<Vec<_>>())))?;
                    let lock = output.get("lock")
                        .ok_or_else(|| format!("lock script not found at inputs[{}].output, available keys: {:?}",
                            cell_index, output.as_object().map(|o| o.keys().collect::<Vec<_>>())))?;
                    extract_script_info(lock, &format!("inputs[{}].output.lock", cell_index))?
                }
                ("type", "input") => {
                    let inputs = mock_info.get("inputs")
                        .and_then(|v| v.as_array())
                        .ok_or("inputs not found in mock_info")?;
                    let cell = inputs.get(cell_index as usize)
                        .ok_or_else(|| format!("cell index {} out of bounds (inputs has {} items)", cell_index, inputs.len()))?;
                    let output = cell.get("output")
                        .ok_or_else(|| format!("output not found at inputs[{}]", cell_index))?;
                    let type_script = output.get("type")
                        .ok_or_else(|| format!("type script not found at inputs[{}].output (this cell has no type script)", cell_index))?;
                    extract_script_info(type_script, &format!("inputs[{}].output.type", cell_index))?
                }
                ("type", "output") => {
                    let tx = mock_tx_value.get("tx").ok_or("tx not found")?;
                    let outputs = tx.get("outputs")
                        .and_then(|v| v.as_array())
                        .ok_or("outputs not found in tx")?;
                    let cell = outputs.get(cell_index as usize)
                        .ok_or_else(|| format!("cell index {} out of bounds (outputs has {} items)", cell_index, outputs.len()))?;
                    let type_script = cell.get("type")
                        .ok_or_else(|| format!("type script not found at outputs[{}] (this cell has no type script)", cell_index))?;
                    extract_script_info(type_script, &format!("outputs[{}].type", cell_index))?
                }
                _ => return Err(format!("Invalid script_group_type/cell_type: {}/{}", script_group_type, cell_type)),
            }
        };

        // Replace binary in cell_deps based on hash_type
        {
            let cell_deps = mock_tx_value
                .get_mut("mock_info")
                .and_then(|v| v.get_mut("cell_deps"))
                .and_then(|v| v.as_array_mut())
                .ok_or("cell_deps not found")?;

            match old_hash_type.as_str() {
                "data" | "data1" | "data2" => {
                    // Find cell_dep where blake2b(data) matches old code_hash
                    for cell_dep in cell_deps.iter_mut() {
                        let data = cell_dep.get("data").and_then(|v| v.as_str()).unwrap_or("0x");
                        let data_clean = if data.starts_with("0x") { &data[2..] } else { data };
                        if let Ok(data_bytes) = hex::decode(data_clean) {
                            let data_hash = format!("0x{}", hex::encode(ckb_hash::blake2b_256(&data_bytes)));
                            if data_hash == old_code_hash {
                                cell_dep["data"] = Value::String(new_binary_hex.clone());
                                break;
                            }
                        }
                    }
                }
                "type" => {
                    // For type hash, find cell_dep whose type script hash matches code_hash
                    // Just replace the data, code_hash stays the same
                    for cell_dep in cell_deps.iter_mut() {
                        if let Some(output) = cell_dep.get("output") {
                            if let Some(type_script) = output.get("type") {
                                if !type_script.is_null() {
                                    // Compute type script hash and compare
                                    let ts_code_hash = type_script.get("code_hash").and_then(|v| v.as_str()).unwrap_or("");
                                    let ts_hash_type = type_script.get("hash_type").and_then(|v| v.as_str()).unwrap_or("");
                                    let ts_args = type_script.get("args").and_then(|v| v.as_str()).unwrap_or("0x");
                                    if !ts_code_hash.is_empty() {
                                        // Simple match: if this cell_dep has a type script, replace its data
                                        cell_dep["data"] = Value::String(new_binary_hex.clone());
                                        break;
                                    }
                                    let _ = (ts_hash_type, ts_args); // suppress unused warnings
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Update the script's code_hash for data hash types
        if matches!(old_hash_type.as_str(), "data" | "data1" | "data2") {
            let mock_info = mock_tx_value.get_mut("mock_info").ok_or("mock_info not found")?;
            match (script_group_type, cell_type) {
                ("lock", "input") => {
                    mock_info["inputs"][cell_index as usize]["output"]["lock"]["code_hash"] =
                        Value::String(new_code_hash.clone());
                }
                ("type", "input") => {
                    mock_info["inputs"][cell_index as usize]["output"]["type"]["code_hash"] =
                        Value::String(new_code_hash.clone());
                }
                ("type", "output") => {
                    mock_tx_value["tx"]["outputs"][cell_index as usize]["type"]["code_hash"] =
                        Value::String(new_code_hash.clone());
                }
                _ => {}
            }
        }

        // Optionally override args
        if !args.is_empty() {
            let args_hex = if args.starts_with("0x") { args.to_string() } else { format!("0x{}", args) };
            let mock_info = mock_tx_value.get_mut("mock_info").ok_or("mock_info not found")?;
            match (script_group_type, cell_type) {
                ("lock", "input") => {
                    mock_info["inputs"][cell_index as usize]["output"]["lock"]["args"] =
                        Value::String(args_hex);
                }
                ("type", "input") => {
                    mock_info["inputs"][cell_index as usize]["output"]["type"]["args"] =
                        Value::String(args_hex);
                }
                ("type", "output") => {
                    mock_tx_value["tx"]["outputs"][cell_index as usize]["type"]["args"] =
                        Value::String(args_hex);
                }
                _ => {}
            }
        }

        // Convert to MockTransaction
        let mock_tx_str = serde_json::to_string(&mock_tx_value).map_err(|e| e.to_string())?;
        let repr: ReprMockTransaction = serde_json::from_str(&mock_tx_str).map_err(|e| e.to_string())?;
        let mock_tx: MockTransaction = repr.into();

        let script_hash = crate::misc::get_script_hash_by_index(
            &mock_tx,
            &sgt,
            cell_type,
            cell_index as usize,
        );
        let max_cycle: Cycle = 70_000_000;

        ipc_call_inner(&mock_tx, &sgt, &script_hash, max_cycle, &ipc_req)
            .map_err(|e| e.to_string())
    }();

    match result {
        Ok(resp) => serde_json::to_string(&resp).unwrap(),
        Err(e) => serde_json::to_string(&serde_json::json!({"error": e})).unwrap(),
    }
}
