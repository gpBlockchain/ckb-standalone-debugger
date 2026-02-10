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
