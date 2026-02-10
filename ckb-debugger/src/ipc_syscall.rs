use ckb_vm::{
    Error, Memory, Register, SupportMachine, Syscalls,
    registers::{A0, A1, A2, A7},
};
use std::sync::{Arc, Mutex};

/// Syscall numbers for IPC pipe operations (same as ckb-script).
const WRITE: u64 = 2605;
const READ: u64 = 2606;
const INHERITED_FD: u64 = 2607;
const CLOSE: u64 = 2608;

/// Maximum read chunk size for a single IPC read syscall.
const MAX_READ_CHUNK_SIZE: usize = 32 * 1024;

/// Fixed file descriptor values for the IPC reader and writer.
const READER_FD: u64 = 0;
const WRITER_FD: u64 = 1;

/// Shared state for IPC buffer-based communication.
/// This replaces pipes for single-threaded WASM environments.
pub struct IpcBufferState {
    pub request_data: Vec<u8>,
    pub request_pos: usize,
    pub response_data: Vec<u8>,
    pub reader_closed: bool,
    pub writer_closed: bool,
}

impl IpcBufferState {
    pub fn new(request_data: Vec<u8>) -> Self {
        Self {
            request_data,
            request_pos: 0,
            response_data: Vec::new(),
            reader_closed: false,
            writer_closed: false,
        }
    }
}

pub type SharedIpcState = Arc<Mutex<IpcBufferState>>;

/// Syscall: INHERITED_FD - returns the reader and writer FDs to the VM.
pub struct IpcInheritedFd {
    state: SharedIpcState,
}

impl IpcInheritedFd {
    pub fn new(state: SharedIpcState) -> Self {
        Self { state }
    }
}

impl<Mac: SupportMachine> Syscalls<Mac> for IpcInheritedFd {
    fn initialize(&mut self, _machine: &mut Mac) -> Result<(), Error> {
        Ok(())
    }

    fn ecall(&mut self, machine: &mut Mac) -> Result<bool, Error> {
        if machine.registers()[A7].to_u64() != INHERITED_FD {
            return Ok(false);
        }
        let _state = self.state.lock().map_err(|e| Error::Unexpected(e.to_string()))?;
        let buffer_addr = machine.registers()[A0].clone();
        let length_addr = machine.registers()[A1].clone();
        let length = machine.memory_mut().load64(&length_addr)?;
        if length.to_u64() < 2 {
            return Err(Error::Unexpected("Length of inherited fd is less than 2".to_string()));
        }
        let mut inherited_fd = [0u8; 16];
        inherited_fd[0x00..0x08].copy_from_slice(&READER_FD.to_le_bytes());
        inherited_fd[0x08..0x10].copy_from_slice(&WRITER_FD.to_le_bytes());
        machine.memory_mut().store_bytes(buffer_addr.to_u64(), &inherited_fd[..])?;
        machine.memory_mut().store64(&length_addr, &Mac::REG::from_u64(2))?;
        machine.set_register(A0, Mac::REG::from_u8(0));
        Ok(true)
    }
}

/// Syscall: READ - reads data from the IPC request buffer.
pub struct IpcRead {
    state: SharedIpcState,
}

impl IpcRead {
    pub fn new(state: SharedIpcState) -> Self {
        Self { state }
    }
}

impl<Mac: SupportMachine> Syscalls<Mac> for IpcRead {
    fn initialize(&mut self, _machine: &mut Mac) -> Result<(), Error> {
        Ok(())
    }

    fn ecall(&mut self, machine: &mut Mac) -> Result<bool, Error> {
        if machine.registers()[A7].to_u64() != READ {
            return Ok(false);
        }
        let fd = machine.registers()[A0].to_u64();
        if fd != READER_FD {
            return Ok(false);
        }
        let mut state = self.state.lock().map_err(|e| Error::Unexpected(e.to_string()))?;
        if state.reader_closed {
            // Return OTHER_END_CLOSED error
            machine.set_register(A0, Mac::REG::from_u8(7));
            return Ok(true);
        }
        let buffer_addr = machine.registers()[A1].clone();
        let length_addr = machine.registers()[A2].clone();
        let length = machine.memory_mut().load64(&length_addr)?.to_u64() as usize;
        let remaining = state.request_data.len() - state.request_pos;
        if remaining == 0 {
            // No more data - signal OTHER_END_CLOSED
            machine.set_register(A0, Mac::REG::from_u8(7));
            return Ok(true);
        }
        let actual = length.min(remaining).min(MAX_READ_CHUNK_SIZE);
        let start = state.request_pos;
        let end = start + actual;
        machine.memory_mut().store_bytes(buffer_addr.to_u64(), &state.request_data[start..end])?;
        machine.memory_mut().store64(&length_addr, &Mac::REG::from_u64(actual as u64))?;
        state.request_pos = end;
        machine.set_register(A0, Mac::REG::from_u8(0));
        Ok(true)
    }
}

/// Syscall: WRITE - writes data to the IPC response buffer.
pub struct IpcWrite {
    state: SharedIpcState,
}

impl IpcWrite {
    pub fn new(state: SharedIpcState) -> Self {
        Self { state }
    }
}

impl<Mac: SupportMachine> Syscalls<Mac> for IpcWrite {
    fn initialize(&mut self, _machine: &mut Mac) -> Result<(), Error> {
        Ok(())
    }

    fn ecall(&mut self, machine: &mut Mac) -> Result<bool, Error> {
        if machine.registers()[A7].to_u64() != WRITE {
            return Ok(false);
        }
        let fd = machine.registers()[A0].to_u64();
        if fd != WRITER_FD {
            return Ok(false);
        }
        let mut state = self.state.lock().map_err(|e| Error::Unexpected(e.to_string()))?;
        if state.writer_closed {
            machine.set_register(A0, Mac::REG::from_u8(7));
            return Ok(true);
        }
        let buffer_addr = machine.registers()[A1].clone();
        let length_addr = machine.registers()[A2].clone();
        let length = machine.memory_mut().load64(&length_addr)?.to_u64();
        if length == 0 {
            machine.set_register(A0, Mac::REG::from_u8(0));
            return Ok(true);
        }
        let data = machine.memory_mut().load_bytes(buffer_addr.to_u64(), length)?;
        state.response_data.extend_from_slice(&data);
        machine.memory_mut().store64(&length_addr, &Mac::REG::from_u64(data.len() as u64))?;
        machine.set_register(A0, Mac::REG::from_u8(0));
        Ok(true)
    }
}

/// Syscall: CLOSE - closes the specified FD.
pub struct IpcClose {
    state: SharedIpcState,
}

impl IpcClose {
    pub fn new(state: SharedIpcState) -> Self {
        Self { state }
    }
}

impl<Mac: SupportMachine> Syscalls<Mac> for IpcClose {
    fn initialize(&mut self, _machine: &mut Mac) -> Result<(), Error> {
        Ok(())
    }

    fn ecall(&mut self, machine: &mut Mac) -> Result<bool, Error> {
        if machine.registers()[A7].to_u64() != CLOSE {
            return Ok(false);
        }
        let fd = machine.registers()[A0].to_u64();
        let mut state = self.state.lock().map_err(|e| Error::Unexpected(e.to_string()))?;
        match fd {
            READER_FD => {
                state.reader_closed = true;
                machine.set_register(A0, Mac::REG::from_u8(0));
                Ok(true)
            }
            WRITER_FD => {
                state.writer_closed = true;
                machine.set_register(A0, Mac::REG::from_u8(0));
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}
